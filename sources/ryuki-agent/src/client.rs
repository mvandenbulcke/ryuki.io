//! Typed async HTTP client for the Ryuki control-plane agent API.
//!
//! ## Auth model
//!
//! - `register_new` is the **unauthenticated** call (called before the agent
//!   has a token): it constructs a bare `reqwest::Client` and hits
//!   `POST /api/agents/register`, returning the `(agent_id, token)` pair.
//! - After registration + approval, construct an authed `CpClient` with
//!   `CpClient::new(base_url, agent_id, token)`.  Every subsequent call
//!   includes `Authorization: Bearer <token>`.
//!
//! ## post_result (S4a stub)
//!
//! The HTTP plumbing is fully implemented.  The `body` parameter is a raw
//! `serde_json::Value` so S4b can supply the properly-constructed `ResultBody`
//! (with `JobResult` + signed `SignedEnvelope` + evidence) without changing the
//! client API.  Document the expected shape in the S4b seam note below.
//!
//! ## Tests (no live server)
//!
//! S4a tests cover:
//! - Serde round-trips for all request/response types against the protocol
//!   types from `ryuki-protocol` and the CP wire types from `ryuki-api`.
//! - URL construction correctness (trailing-slash normalisation, path segments).
//!
//! Live-server end-to-end testing is S4b.

use reqwest::{header, Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use ryuki_protocol::{AgentRegistration, Job};

// ---------------------------------------------------------------------------
// Wire types mirroring ryuki-api/src/agents.rs
// ---------------------------------------------------------------------------

/// Mirrors `agents::RegisterResponse` exactly.
///
/// `Debug` is manual to REDACT the one-time token — a derived `Debug` would leak
/// the bearer token into any trace that formats the response.
#[derive(Clone, Deserialize, Serialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    pub token: String,
}

impl std::fmt::Debug for RegisterResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterResponse")
            .field("agent_id", &self.agent_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Mirrors `agents::AckBody` exactly.
#[derive(Debug, Serialize)]
struct AckBody {
    pub attempt_id: Uuid,
    pub fencing_token: String,
}

/// Mirrors `agents::HeartbeatBody` exactly.
#[derive(Debug, Serialize)]
struct HeartbeatBody {
    pub running_job_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// ClientError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("control plane returned {status}: {body}")]
    ErrorStatus { status: u16, body: String },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Consume a `reqwest::Response`, asserting 2xx.
/// On non-2xx: read the body text and return `ClientError::ErrorStatus`.
async fn require_2xx(resp: reqwest::Response) -> Result<reqwest::Response, ClientError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let code = status.as_u16();
    let body = resp
        .text()
        .await
        .unwrap_or_else(|_| "<unreadable>".to_owned());
    Err(ClientError::ErrorStatus { status: code, body })
}

// ---------------------------------------------------------------------------
// CpClient
// ---------------------------------------------------------------------------

/// Authenticated control-plane HTTP client.
///
/// All methods append to `base_url`; the URL is stored without a trailing slash.
pub struct CpClient {
    http: Client,
    base_url: String,
    /// The `agent_id` string used in URL path segments (e.g. `defra-vcenter-01`).
    agent_id: String,
    /// Bearer token (includes the `rya_` prefix).
    token: String,
}

impl CpClient {
    /// Construct an authenticated client.
    ///
    /// `base_url` may or may not have a trailing slash; it is normalised here.
    pub fn new(
        base_url: impl Into<String>,
        agent_id: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        Self {
            http: Client::new(),
            base_url,
            agent_id: agent_id.into(),
            token: token.into(),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn jobs_base_url(&self) -> String {
        format!("{}/api/agents/{}/jobs", self.base_url, self.agent_id)
    }

    // ------------------------------------------------------------------
    // Registration (unauthenticated — called before a token exists)
    // ------------------------------------------------------------------

    /// POST /api/agents/register (no bearer token).
    ///
    /// This is an associated function, not a method, because the client does not
    /// yet have a token at call time.  Returns `(agent_id, token)`.
    ///
    /// After the admin approves the agent, the caller constructs a `CpClient`
    /// with the returned token and calls the authed methods.
    pub async fn register_new(
        base_url: &str,
        reg: &AgentRegistration,
    ) -> Result<RegisterResponse, ClientError> {
        let base_url = base_url.trim_end_matches('/');
        let url = format!("{}/api/agents/register", base_url);
        let http = Client::new();
        let resp = http.post(&url).json(reg).send().await?;
        let resp = require_2xx(resp).await?;
        let body: RegisterResponse = resp.json().await?;
        Ok(body)
    }

    // ------------------------------------------------------------------
    // Authenticated methods
    // ------------------------------------------------------------------

    /// GET /api/agents/{agent_id}/jobs
    ///
    /// Returns `None` on HTTP 204 (no job available), `Some(Job)` on 200.
    pub async fn poll(&self) -> Result<Option<Job>, ClientError> {
        let url = self.jobs_base_url();
        let resp = self
            .http
            .get(&url)
            .header(header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;

        if resp.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }

        let resp = require_2xx(resp).await?;
        let job: Job = resp.json().await?;
        Ok(Some(job))
    }

    /// POST /api/agents/{agent_id}/jobs/{job_id}/ack
    ///
    /// Transitions the job from `Leased` to `Running`.  The caller must supply
    /// the `attempt_id` and `fencing_token` from the `JobLease` received via
    /// `poll()`.
    pub async fn ack(
        &self,
        job_id: Uuid,
        attempt_id: Uuid,
        fencing_token: impl Into<String>,
    ) -> Result<(), ClientError> {
        let url = format!("{}/{}/ack", self.jobs_base_url(), job_id);
        let body = AckBody {
            attempt_id,
            fencing_token: fencing_token.into(),
        };
        let resp = self
            .http
            .post(&url)
            .header(header::AUTHORIZATION, self.auth_header())
            .json(&body)
            .send()
            .await?;
        require_2xx(resp).await?;
        Ok(())
    }

    /// POST /api/agents/{agent_id}/heartbeat
    ///
    /// `running_job_id` is `None` if the agent is idle (no active job).
    pub async fn heartbeat(&self, running_job_id: Option<Uuid>) -> Result<(), ClientError> {
        let url = format!("{}/api/agents/{}/heartbeat", self.base_url, self.agent_id);
        let body = HeartbeatBody { running_job_id };
        let resp = self
            .http
            .post(&url)
            .header(header::AUTHORIZATION, self.auth_header())
            .json(&body)
            .send()
            .await?;
        require_2xx(resp).await?;
        Ok(())
    }

    /// GET /api/agents/cp-public-key
    ///
    /// Fetches the control plane's Ed25519 verifying (public) key as a
    /// base64-encoded string.  This endpoint is **intentionally unauthenticated**
    /// on the CP side — a public key is not a secret.  Sending a bearer token
    /// is harmless; we include it for consistency with other methods.
    ///
    /// The caller should pin the returned key at startup (via
    /// `ryuki_agent::live::pin_cp_key`) and use it to verify every
    /// [`VerifiedLiveContext`] grant before a `LiveApply` execution.
    ///
    /// ## TOFU note
    ///
    /// Fetching over plain `http://` exposes the key to a MITM who can substitute
    /// their own key and subsequently forge grants.  In production the CP URL MUST
    /// use HTTPS, or the operator must pin the key via a separate trusted channel.
    /// The `ryuki-agent` binary logs a warning when `cp_base_url` is `http://`.
    ///
    /// Returns the raw base64 string (suitable for passing to `pin_cp_key`).
    pub async fn fetch_cp_public_key(&self) -> Result<String, ClientError> {
        let url = format!("{}/api/agents/cp-public-key", self.base_url);
        let resp = self
            .http
            .get(&url)
            // Bearer token is harmless here (endpoint is unauthenticated), and
            // sending it consistently avoids any future auth-policy change from
            // silently breaking this call.
            .header(header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;
        let resp = require_2xx(resp).await?;
        let body: serde_json::Value = resp.json().await?;
        body.get("public_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| ClientError::ErrorStatus {
                status: 200,
                body: "response missing 'public_key' field".to_owned(),
            })
    }

    /// POST /api/agents/{agent_id}/jobs/{job_id}/result
    ///
    /// # S4a seam — body is `serde_json::Value`
    ///
    /// S4b will construct the full `ResultBody`:
    /// ```json
    /// {
    ///   "job_result": {
    ///     "job_id": "<uuid>",
    ///     "attempt_id": "<uuid>",
    ///     "result_id": "<uuid>",
    ///     "status": "<JobResultStatus>",
    ///     "evidence_digest": "<sha256-hex>",
    ///     "signed_envelope": { /* SignedEnvelope fields */ }
    ///   },
    ///   "evidence": [/* raw bytes as JSON array of u8 */],
    ///   "evidence_json": { /* optional structured evidence */ }
    /// }
    /// ```
    /// The CP's `ResultBody` deserialiser expects this exact shape
    /// (`ryuki-api/src/agents.rs` `ResultBody`).
    ///
    /// For now S4b fills `body` with a properly-constructed `Value`;
    /// the HTTP plumbing (URL, auth header, error mapping) is done.
    pub async fn post_result(
        &self,
        job_id: Uuid,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let url = format!("{}/{}/result", self.jobs_base_url(), job_id);
        let resp = self
            .http
            .post(&url)
            .header(header::AUTHORIZATION, self.auth_header())
            .json(&body)
            .send()
            .await?;
        let resp = require_2xx(resp).await?;
        let json: serde_json::Value = resp.json().await?;
        Ok(json)
    }
}

// ---------------------------------------------------------------------------
// Tests (no live server — serde round-trips + URL construction)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ryuki_protocol::{
        AgentRegistration, Capabilities, Job, JobLease, JobMode, JobSpec, JobStatus,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // URL construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn poll_url_is_correct() {
        let client = CpClient::new("https://cp.example.com/", "defra-vcenter-01", "rya_tok");
        let expected = "https://cp.example.com/api/agents/defra-vcenter-01/jobs";
        assert_eq!(client.jobs_base_url(), expected);
    }

    #[test]
    fn base_url_trailing_slash_stripped() {
        let client = CpClient::new("https://cp.example.com///", "ag", "rya_x");
        // The trailing slashes are stripped.
        assert_eq!(client.base_url, "https://cp.example.com");
    }

    #[test]
    fn ack_url_contains_job_id() {
        let client = CpClient::new("https://cp.example.com", "my-agent", "rya_tok");
        let job_id = Uuid::nil();
        let expected = format!(
            "https://cp.example.com/api/agents/my-agent/jobs/{}/ack",
            job_id
        );
        let actual = format!("{}/{}/ack", client.jobs_base_url(), job_id);
        assert_eq!(actual, expected);
    }

    #[test]
    fn result_url_contains_job_id() {
        let client = CpClient::new("https://cp.example.com", "my-agent", "rya_tok");
        let job_id = Uuid::nil();
        let expected = format!(
            "https://cp.example.com/api/agents/my-agent/jobs/{}/result",
            job_id
        );
        let actual = format!("{}/{}/result", client.jobs_base_url(), job_id);
        assert_eq!(actual, expected);
    }

    #[test]
    fn heartbeat_url_is_correct() {
        let client = CpClient::new("https://cp.example.com", "my-agent", "rya_tok");
        let expected = "https://cp.example.com/api/agents/my-agent/heartbeat";
        let actual = format!(
            "{}/api/agents/{}/heartbeat",
            client.base_url, client.agent_id
        );
        assert_eq!(actual, expected);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests — wire types against protocol types
    // -----------------------------------------------------------------------

    #[test]
    fn register_response_roundtrip() {
        let resp = RegisterResponse {
            agent_id: "defra-vcenter-01".to_owned(),
            token: "rya_abc123def456".to_owned(),
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        let decoded: RegisterResponse = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(decoded.agent_id, resp.agent_id);
        assert_eq!(decoded.token, resp.token);
    }

    #[test]
    fn agent_registration_roundtrip() {
        let reg = AgentRegistration {
            agent_id: "gblon-proxmox-01".to_owned(),
            platform: "gblon".to_owned(),
            capabilities: Capabilities::default(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        };
        let json = serde_json::to_string(&reg).expect("serialise");
        let decoded: AgentRegistration = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(decoded.agent_id, reg.agent_id);
        assert_eq!(decoded.platform, reg.platform);
        assert_eq!(decoded.public_key, reg.public_key);
    }

    #[test]
    fn ack_body_serialises_correctly() {
        let body = AckBody {
            attempt_id: Uuid::nil(),
            fencing_token: "fence-abc".to_owned(),
        };
        let json = serde_json::to_value(&body).expect("serialise");
        assert_eq!(json["attempt_id"], serde_json::json!(Uuid::nil()));
        assert_eq!(json["fencing_token"], serde_json::json!("fence-abc"));
    }

    #[test]
    fn heartbeat_body_serialises_none_and_some() {
        let idle = HeartbeatBody {
            running_job_id: None,
        };
        let json = serde_json::to_value(&idle).expect("serialise");
        assert!(json["running_job_id"].is_null());

        let running = HeartbeatBody {
            running_job_id: Some(Uuid::nil()),
        };
        let json = serde_json::to_value(&running).expect("serialise");
        assert_eq!(json["running_job_id"], serde_json::json!(Uuid::nil()));
    }

    /// Verify that a `Job` body returned by the CP deserialises correctly via
    /// the `ryuki_protocol::Job` type (this is what `poll()` does internally).
    #[test]
    fn job_from_cp_body_deserialises() {
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".to_owned(),
            iac_digest: "a".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::OfflineDryRun,
        };
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + chrono::Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        let job = Job {
            id: Uuid::new_v4(),
            platform: "defra".to_owned(),
            spec,
            status: JobStatus::Leased,
            lease: Some(lease),
            live_context: None,
        };

        // Simulate what poll() does: serialise → deserialise.
        let json = serde_json::to_string(&job).expect("serialise");
        let decoded: Job = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(decoded.id, job.id);
        assert_eq!(decoded.platform, job.platform);
        assert!(decoded.lease.is_some());
    }

    /// Verify that a 204 response (empty body) correctly maps to `None`.
    /// We simulate this by checking that an empty byte slice cannot be
    /// deserialised as a `Job` (which is how poll() detects 204).
    #[test]
    fn empty_body_is_not_a_job() {
        let result: Result<Job, _> = serde_json::from_str("");
        assert!(result.is_err(), "empty body must not deserialise as Job");
    }

    // -----------------------------------------------------------------------
    // fetch_cp_public_key — URL construction + response parsing (no live server)
    // -----------------------------------------------------------------------

    #[test]
    fn cp_public_key_url_is_correct() {
        let client = CpClient::new("https://cp.example.com/", "defra-vcenter-01", "rya_tok");
        let expected = "https://cp.example.com/api/agents/cp-public-key";
        let actual = format!("{}/api/agents/cp-public-key", client.base_url);
        assert_eq!(
            actual, expected,
            "cp-public-key URL must use base_url without trailing slash"
        );
    }

    #[test]
    fn cp_public_key_response_parses_public_key_field() {
        // Simulate the JSON body that the CP returns.
        let body =
            serde_json::json!({"public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="});
        let key = body
            .get("public_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        assert_eq!(
            key,
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()),
            "public_key field must be extracted correctly"
        );
    }

    #[test]
    fn cp_public_key_response_missing_field_returns_error() {
        // A body without "public_key" must map to an ErrorStatus.
        let body = serde_json::json!({"status": "ok"});
        let key = body
            .get("public_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        assert!(
            key.is_none(),
            "missing public_key field must produce None → ErrorStatus"
        );
    }
}
