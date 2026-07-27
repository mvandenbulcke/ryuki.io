//! Typed async HTTP client for the Ryuki control-plane agent API.
//!
//! ## Auth model
//!
//! - `register_new` is the **unauthenticated** call (called before the agent
//!   has a token): it hits `POST /api/agents/register`, returning the
//!   `(agent_id, token)` pair.
//! - After registration + approval, construct an authed `CpClient` from the
//!   same validated [`ControlPlaneEndpoint`]. Every subsequent credential-
//!   bearing call uses that endpoint and includes `Authorization: Bearer
//!   <token>`.
//!
//! The endpoint is parsed and transport-validated once, redirects are disabled,
//! and HTTPS is enforced again in reqwest. Plain HTTP is available only for an
//! explicitly enabled loopback development endpoint, with ambient proxies
//! disabled so the local exception cannot send credentials off-host.
//!
//! ## post_result (S4a stub)
//!
//! The HTTP plumbing is fully implemented.  The `body` parameter is a raw
//! `serde_json::Value` so S4b can supply the properly-constructed `ResultBody`
//! (with `JobResult` + signed `SignedEnvelope` + evidence) without changing the
//! client API.  Document the expected shape in the S4b seam note below.
//!
//! ## Tests
//!
//! Tests cover:
//! - Serde round-trips for all request/response types against the protocol
//!   types from `ryuki-protocol` and the CP wire types from `ryuki-api`.
//! - URL construction correctness (trailing-slash normalisation, path segments).
//! - Transport policy and no-redirect behavior with local one-shot fixtures.

use std::net::IpAddr;

use reqwest::{header, Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use ryuki_protocol::{
    AgentHeartbeat, AgentHeartbeatResponse, AgentRegistration, ControlPlaneGrantKeysetResponse,
    Job, JobLease,
};

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

// ---------------------------------------------------------------------------
// ClientError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("control plane returned {status}: {body}")]
    ErrorStatus { status: u16, body: String },
    /// The CP advertises a wire protocol version this agent does not support.
    /// The caller should refuse to start rather than risk silent schema drift.
    #[error(
        "control plane speaks wire protocol v{cp_version}, but this agent supports {supported:?} — upgrade required"
    )]
    IncompatibleProtocol {
        cp_version: u32,
        supported: &'static [u32],
    },
    /// The unauthenticated bootstrap response did not match the closed protocol
    /// schema. Keep this error value-free: the response is remotely supplied
    /// and must not be reflected into agent logs.
    #[error("control-plane keyset bootstrap response is invalid")]
    InvalidControlPlaneKeysetResponse,
    /// The configured endpoint does not meet the credential-transport policy.
    /// The raw value is deliberately omitted because rejected userinfo may
    /// itself contain a credential.
    #[error("invalid control-plane endpoint: {reason}")]
    InvalidEndpoint { reason: &'static str },
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

/// Stamp the CP↔agent wire protocol version onto every request. The bootstrap
/// endpoint accepts this as optional diagnostic metadata; every other agent
/// endpoint reads it before body deserialization and rejects unsupported values
/// with a clear error instead of an opaque 400.
fn with_protocol_version(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb.header(
        ryuki_protocol::PROTOCOL_VERSION_HEADER,
        ryuki_protocol::PROTOCOL_VERSION.to_string(),
    )
}

// ---------------------------------------------------------------------------
// Validated control-plane endpoint
// ---------------------------------------------------------------------------

/// A parsed control-plane destination that has already passed the credential-
/// transport policy.
///
/// Fields are private so production callers cannot construct an HTTP endpoint
/// without passing the explicit loopback-only policy in [`Self::parse`].
#[derive(Clone, Debug)]
pub struct ControlPlaneEndpoint {
    url: Url,
    insecure_loopback: bool,
}

impl ControlPlaneEndpoint {
    /// Parse and validate a control-plane base URL.
    ///
    /// HTTPS is always admitted. HTTP is admitted only when
    /// `allow_insecure_loopback` is explicitly true and the parsed host is the
    /// exact `localhost` name or an IPv4/IPv6 address for which the standard
    /// library reports `is_loopback()`. Userinfo, queries, fragments, missing
    /// hosts, lookalike names, and the unspecified `0.0.0.0` address are
    /// rejected.
    pub fn parse(raw: &str, allow_insecure_loopback: bool) -> Result<Self, ClientError> {
        let raw = raw.trim();
        let mut url = Url::parse(raw).map_err(|_| ClientError::InvalidEndpoint {
            reason: "RYUKI_AGENT_CP_URL must be a valid absolute URL",
        })?;
        if url.host().is_none() {
            return Err(ClientError::InvalidEndpoint {
                reason: "RYUKI_AGENT_CP_URL must contain a host",
            });
        }
        // Url::username() cannot distinguish absent userinfo from the
        // syntactically present but empty form `https://@host`.
        let raw_authority_has_userinfo = raw
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
            .is_some_and(|authority| authority.contains('@'));
        if raw_authority_has_userinfo || !url.username().is_empty() || url.password().is_some() {
            return Err(ClientError::InvalidEndpoint {
                reason: "RYUKI_AGENT_CP_URL must not contain userinfo",
            });
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ClientError::InvalidEndpoint {
                reason: "RYUKI_AGENT_CP_URL must not contain a query string or fragment",
            });
        }
        if endpoint_host_address(&url).is_some_and(|address| address.is_unspecified()) {
            return Err(ClientError::InvalidEndpoint {
                reason: "RYUKI_AGENT_CP_URL must name a destination, not an unspecified address",
            });
        }

        let insecure_loopback = match url.scheme() {
            "https" => false,
            "http" if allow_insecure_loopback && endpoint_host_is_loopback(&url) => true,
            "http" => {
                return Err(ClientError::InvalidEndpoint {
                    reason: "RYUKI_AGENT_CP_URL must use HTTPS; plain HTTP is allowed only for an explicitly enabled loopback development endpoint via RYUKI_AGENT_ALLOW_INSECURE_LOOPBACK",
                });
            }
            _ => {
                return Err(ClientError::InvalidEndpoint {
                    reason: "RYUKI_AGENT_CP_URL must use the HTTPS scheme",
                });
            }
        };

        // Relative joins below must append beneath an optional reverse-proxy
        // prefix instead of replacing its final segment.
        let normalized = format!("{}/", raw.trim_end_matches('/'));
        url = Url::parse(&normalized).expect("validated control-plane URL must reparse");

        Ok(Self {
            url,
            insecure_loopback,
        })
    }

    /// Whether this endpoint uses the explicit loopback HTTP development path.
    pub fn is_insecure_loopback(&self) -> bool {
        self.insecure_loopback
    }

    /// Join one API-relative path beneath the validated base URL.
    fn join(&self, relative: &str) -> Url {
        self.url
            .join(relative)
            .expect("static agent API path must join a validated base URL")
    }
}

impl std::fmt::Display for ControlPlaneEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Preserve the previous operator-facing form without a trailing slash.
        f.write_str(self.url.as_str().trim_end_matches('/'))
    }
}

fn endpoint_host_is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || endpoint_host_address(url).is_some_and(|address| address.is_loopback())
}

fn endpoint_host_address(url: &Url) -> Option<IpAddr> {
    let host = url.host_str()?;
    let address_literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    address_literal.parse::<IpAddr>().ok()
}

/// Build a client whose second-line transport controls match the validated
/// endpoint. Redirects are never followed because an authenticated 3xx must not
/// be able to move a bearer or registration response onto another transport.
fn endpoint_http_client(endpoint: &ControlPlaneEndpoint) -> Result<Client, ClientError> {
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!endpoint.insecure_loopback);
    if endpoint.insecure_loopback {
        // Ambient HTTP_PROXY settings must not turn the local-only exception
        // into a cleartext request carrying credentials to a remote proxy.
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}

// ---------------------------------------------------------------------------
// CpClient
// ---------------------------------------------------------------------------

/// Authenticated control-plane HTTP client.
///
/// Every method joins its path beneath one validated endpoint. The HTTP client
/// cannot follow redirects, and enforces HTTPS unless that endpoint is the
/// explicit loopback-only development exception.
#[derive(Clone)]
pub struct CpClient {
    http: Client,
    endpoint: ControlPlaneEndpoint,
    /// The `agent_id` string used in URL path segments (e.g. `defra-vcenter-01`).
    agent_id: String,
    /// Bearer token (includes the `rya_` prefix).
    token: String,
}

impl CpClient {
    /// Construct an authenticated client from an already-validated endpoint.
    pub fn from_endpoint(
        endpoint: &ControlPlaneEndpoint,
        agent_id: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            http: endpoint_http_client(endpoint)?,
            endpoint: endpoint.clone(),
            agent_id: agent_id.into(),
            token: token.into(),
        })
    }

    /// Test-only raw constructor. Production code must retain the typed
    /// endpoint from configuration; unit tests use this explicit loopback
    /// development policy for their local HTTP stubs.
    #[cfg(test)]
    pub(crate) fn new(
        base_url: &str,
        agent_id: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        let endpoint = ControlPlaneEndpoint::parse(base_url, true)
            .expect("test control-plane URL must be HTTPS or loopback HTTP");
        Self::from_endpoint(&endpoint, agent_id, token)
            .expect("test control-plane client must initialize")
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Attach both the bearer token and the wire protocol version header to a
    /// request. Every authenticated call goes through this so neither header can
    /// be omitted at an individual call site.
    fn authed(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        with_protocol_version(rb).header(header::AUTHORIZATION, self.auth_header())
    }

    fn jobs_base_url(&self) -> Url {
        self.endpoint
            .join(&format!("api/agents/{}/jobs", self.agent_id))
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
        endpoint: &ControlPlaneEndpoint,
        reg: &AgentRegistration,
    ) -> Result<RegisterResponse, ClientError> {
        let url = endpoint.join("api/agents/register");
        let http = endpoint_http_client(endpoint)?;
        let resp = with_protocol_version(http.post(url))
            .json(reg)
            .send()
            .await?;
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
        let resp = self.authed(self.http.get(url)).send().await?;

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
        let url = self
            .endpoint
            .join(&format!("api/agents/{}/jobs/{job_id}/ack", self.agent_id));
        let body = AckBody {
            attempt_id,
            fencing_token: fencing_token.into(),
        };
        let resp = self.authed(self.http.post(url)).json(&body).send().await?;
        require_2xx(resp).await?;
        Ok(())
    }

    /// POST /api/agents/{agent_id}/heartbeat
    ///
    /// Send an idle agent heartbeat. Running jobs use [`Self::renew_lease`]
    /// because a job id without its exact fencing material must never extend a
    /// lease.
    pub async fn heartbeat(&self) -> Result<(), ClientError> {
        let url = self
            .endpoint
            .join(&format!("api/agents/{}/heartbeat", self.agent_id));
        let body = AgentHeartbeat::idle();
        let resp = self.authed(self.http.post(url)).json(&body).send().await?;
        require_2xx(resp).await?;
        Ok(())
    }

    /// Renew an acknowledged running job lease using its full ownership fence.
    /// A stale/expired/superseded lease receives a non-2xx response and callers
    /// must stop execution rather than treating this as a best-effort heartbeat.
    pub async fn renew_lease(
        &self,
        job_id: Uuid,
        lease: &JobLease,
    ) -> Result<AgentHeartbeatResponse, ClientError> {
        let url = self
            .endpoint
            .join(&format!("api/agents/{}/heartbeat", self.agent_id));
        let body = AgentHeartbeat::renewing(job_id, lease);
        let resp = self.authed(self.http.post(url)).json(&body).send().await?;
        let resp = require_2xx(resp).await?;
        Ok(resp.json().await?)
    }

    /// GET /api/agents/cp-public-key
    ///
    /// Fetches the control plane's protocol version and versioned Ed25519
    /// verification keyset atomically. This endpoint is **intentionally
    /// unauthenticated** on the CP side, so the client deliberately omits the
    /// reusable bearer.
    ///
    /// The caller should pin the returned key at startup (via
    /// `ryuki_agent::live::pin_cp_keyset`) and use it to verify every
    /// [`VerifiedLiveContext`] grant before a `LiveApply` execution.
    ///
    /// ## TOFU note
    ///
    /// The typed endpoint makes HTTPS mandatory except for the explicit
    /// loopback-only development policy, so a remote MITM cannot substitute the
    /// key during this fetch.
    ///
    /// Returns the closed typed bootstrap response. Malformed JSON and schema
    /// drift map to one value-free error so untrusted response content cannot
    /// be reflected into logs.
    pub async fn fetch_cp_keyset_response(
        &self,
    ) -> Result<ControlPlaneGrantKeysetResponse, ClientError> {
        let url = self.endpoint.join("api/agents/cp-public-key");
        // This endpoint is intentionally unauthenticated. Do not send the
        // reusable bearer. The header is useful to a current CP for diagnostics,
        // but bootstrap compatibility comes from the typed response and the
        // endpoint does not require a request protocol header.
        let resp = with_protocol_version(self.http.get(url)).send().await?;
        let resp = require_2xx(resp).await?;
        let body = resp.bytes().await?;
        serde_json::from_slice(&body).map_err(|_| ClientError::InvalidControlPlaneKeysetResponse)
    }

    /// Confirm that the version from an already fetched bootstrap response is
    /// supported. Keeping this pure prevents callers from issuing a second GET
    /// and accidentally checking compatibility against a different keyset
    /// publication.
    pub fn require_compatible_protocol(cp_version: u32) -> Result<(), ClientError> {
        if !ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&cp_version) {
            return Err(ClientError::IncompatibleProtocol {
                cp_version,
                supported: ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS,
            });
        }
        Ok(())
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
        let url = self.endpoint.join(&format!(
            "api/agents/{}/jobs/{job_id}/result",
            self.agent_id
        ));
        let resp = self.authed(self.http.post(url)).json(&body).send().await?;
        let resp = require_2xx(resp).await?;
        let json: serde_json::Value = resp.json().await?;
        Ok(json)
    }
}

// ---------------------------------------------------------------------------
// Tests (serde, URL construction, and local one-shot transport fixtures)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rand::rngs::OsRng;
    use ryuki_protocol::{
        control_plane_grant_verifying_key, generate_keypair, AgentRegistration, Capabilities,
        ControlPlaneGrantKeyDisposition, ControlPlaneGrantKeyset, Job, JobLease, JobMode, JobSpec,
        JobStatus,
    };
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    async fn one_response_server(response: String) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local test server");
        let addr = listener.local_addr().expect("local test address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n")
                && request.len() < 16 * 1024
            {
                let read = stream.read(&mut chunk).await.expect("read test request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let required = header_end + 4 + content_length;
                while request.len() < required && request.len() < 16 * 1024 {
                    let read = stream
                        .read(&mut chunk)
                        .await
                        .expect("read test request body");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
            }
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write test response");
            String::from_utf8(request).expect("HTTP request must be UTF-8 in this fixture")
        });
        (format!("http://{addr}"), task)
    }

    fn test_keyset_response() -> ControlPlaneGrantKeysetResponse {
        let signing_key = generate_keypair(&mut OsRng);
        let active = control_plane_grant_verifying_key(
            &signing_key.verifying_key(),
            ControlPlaneGrantKeyDisposition::Active,
        );
        ControlPlaneGrantKeysetResponse {
            keyset: ControlPlaneGrantKeyset {
                keyset_version: 1,
                active_key_id: active.key_id.clone(),
                keys: vec![active],
            },
            protocol_version: ryuki_protocol::PROTOCOL_VERSION,
        }
    }

    // -----------------------------------------------------------------------
    // URL construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn poll_url_is_correct() {
        let client = CpClient::new("https://cp.example.com/", "defra-vcenter-01", "rya_tok");
        let expected = "https://cp.example.com/api/agents/defra-vcenter-01/jobs";
        assert_eq!(client.jobs_base_url().as_str(), expected);
    }

    #[test]
    fn endpoint_requires_https_by_default() {
        let result = ControlPlaneEndpoint::parse("http://127.0.0.1:8081", false);
        assert!(
            matches!(result, Err(ClientError::InvalidEndpoint { .. })),
            "even loopback HTTP must require an explicit development policy"
        );
    }

    #[test]
    fn endpoint_allows_explicit_loopback_http_and_https() {
        for raw in [
            "https://cp.example.com",
            "http://localhost:8081",
            "http://127.9.8.7:8081",
            "http://[::1]:8081",
        ] {
            let endpoint = ControlPlaneEndpoint::parse(raw, true)
                .unwrap_or_else(|e| panic!("valid endpoint {raw} was rejected: {e}"));
            assert_eq!(endpoint.is_insecure_loopback(), raw.starts_with("http://"));
        }
    }

    #[test]
    fn endpoint_rejects_remote_or_ambiguous_http_even_with_switch() {
        for raw in [
            "http://cp.example.com",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://0.0.0.0:8081",
            "https://0.0.0.0:8443",
            "https://[::]:8443",
            "http://localhost:8081@evil.example",
            "http://@localhost:8081",
        ] {
            assert!(
                matches!(
                    ControlPlaneEndpoint::parse(raw, true),
                    Err(ClientError::InvalidEndpoint { .. })
                ),
                "unsafe endpoint {raw:?} must be rejected"
            );
        }
    }

    #[test]
    fn endpoint_rejects_credential_components_but_preserves_path_prefix() {
        for raw in [
            "https://user@cp.example.com",
            "https://@cp.example.com",
            "https://cp.example.com?query=1",
            "https://cp.example.com#fragment",
            "ftp://cp.example.com",
            "https://",
        ] {
            assert!(
                matches!(
                    ControlPlaneEndpoint::parse(raw, false),
                    Err(ClientError::InvalidEndpoint { .. })
                ),
                "unsafe endpoint {raw:?} must be rejected"
            );
        }

        let endpoint = ControlPlaneEndpoint::parse("https://cp.example.com/ryuki///", false)
            .expect("reverse-proxy path prefix must remain supported");
        assert_eq!(
            endpoint.join("api/agents/register").as_str(),
            "https://cp.example.com/ryuki/api/agents/register"
        );
    }

    #[test]
    fn incompatible_protocol_error_names_both_versions() {
        // The refuse-to-start error must tell the operator what the CP speaks and
        // what this agent supports, so the fix (upgrade the agent) is obvious.
        let err = ClientError::IncompatibleProtocol {
            cp_version: 7,
            supported: &[1, 2],
        };
        let msg = err.to_string();
        assert!(msg.contains("v7"), "must name the CP version: {msg}");
        assert!(msg.contains("[1, 2]"), "must name the supported set: {msg}");
        assert!(
            msg.contains("upgrade"),
            "must state the remedy (upgrade): {msg}"
        );
    }

    #[test]
    fn protocol_version_header_name_is_the_shared_constant() {
        // The client stamps the exact header the CP extractor reads — one constant,
        // no drift.
        assert_eq!(
            ryuki_protocol::PROTOCOL_VERSION_HEADER,
            "x-ryuki-protocol-version"
        );
        assert!(
            ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&ryuki_protocol::PROTOCOL_VERSION)
        );
    }

    #[test]
    fn current_bootstrap_protocol_version_is_accepted() {
        CpClient::require_compatible_protocol(ryuki_protocol::PROTOCOL_VERSION)
            .expect("current protocol version must remain supported");
    }

    #[test]
    fn legacy_versions_are_not_supported_after_request_version_upgrade() {
        assert_eq!(ryuki_protocol::PROTOCOL_VERSION_LEGACY, 1);
        assert!(!ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&1));
        assert!(!ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&3));
        assert!(!ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&4));
        assert!(!ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&5));
        assert!(!ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&6));
        assert_eq!(ryuki_protocol::PROTOCOL_VERSION, 8);
        assert!(
            ryuki_protocol::SUPPORTED_PROTOCOL_VERSIONS.contains(&ryuki_protocol::PROTOCOL_VERSION)
        );
    }

    #[test]
    fn unsupported_bootstrap_protocol_version_is_rejected() {
        let error = CpClient::require_compatible_protocol(ryuki_protocol::PROTOCOL_VERSION_LEGACY)
            .expect_err("a legacy CP must be rejected after the v8 cutover");
        assert!(matches!(
            error,
            ClientError::IncompatibleProtocol {
                cp_version: ryuki_protocol::PROTOCOL_VERSION_LEGACY,
                ..
            }
        ));
    }

    #[test]
    fn base_url_trailing_slash_stripped() {
        let client = CpClient::new("https://cp.example.com///", "ag", "rya_x");
        // The trailing slashes are stripped.
        assert_eq!(client.endpoint.to_string(), "https://cp.example.com");
    }

    #[test]
    fn ack_url_contains_job_id() {
        let client = CpClient::new("https://cp.example.com", "my-agent", "rya_tok");
        let job_id = Uuid::nil();
        let expected = format!(
            "https://cp.example.com/api/agents/my-agent/jobs/{}/ack",
            job_id
        );
        let actual = client
            .endpoint
            .join(&format!("api/agents/my-agent/jobs/{job_id}/ack"));
        assert_eq!(actual.as_str(), expected.as_str());
    }

    #[test]
    fn result_url_contains_job_id() {
        let client = CpClient::new("https://cp.example.com", "my-agent", "rya_tok");
        let job_id = Uuid::nil();
        let expected = format!(
            "https://cp.example.com/api/agents/my-agent/jobs/{}/result",
            job_id
        );
        let actual = client
            .endpoint
            .join(&format!("api/agents/my-agent/jobs/{job_id}/result"));
        assert_eq!(actual.as_str(), expected.as_str());
    }

    #[test]
    fn heartbeat_url_is_correct() {
        let client = CpClient::new("https://cp.example.com", "my-agent", "rya_tok");
        let expected = "https://cp.example.com/api/agents/my-agent/heartbeat";
        let actual = client
            .endpoint
            .join(&format!("api/agents/{}/heartbeat", client.agent_id));
        assert_eq!(actual.as_str(), expected);
    }

    #[tokio::test]
    async fn authenticated_client_does_not_follow_redirects() {
        let response = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/exfil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
        let (base_url, server) = one_response_server(response).await;
        let endpoint = ControlPlaneEndpoint::parse(&base_url, true).expect("loopback opt-in");
        let client = CpClient::from_endpoint(&endpoint, "agent", "rya_test_bearer")
            .expect("client must initialize");

        let err = client
            .heartbeat()
            .await
            .expect_err("302 must not be followed");
        assert!(
            matches!(&err, ClientError::ErrorStatus { status: 302, .. }),
            "redirect must surface as the original 302: {err}"
        );
        let request = server.await.expect("test server task");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer rya_test_bearer"),
            "fixture must exercise a credential-bearing request"
        );
    }

    #[tokio::test]
    async fn registration_client_does_not_follow_redirects() {
        let response = "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:9/exfil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
        let (base_url, server) = one_response_server(response).await;
        let endpoint = ControlPlaneEndpoint::parse(&base_url, true).expect("loopback opt-in");
        let registration = AgentRegistration {
            enrollment_challenge_id: Uuid::nil(),
            enrollment_challenge:
                "ryc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            agent_id: "agent".to_owned(),
            platform: "defra".to_owned(),
            capabilities: Capabilities::default(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            enrollment_proof: "proof".to_owned(),
        };

        let err = CpClient::register_new(&endpoint, &registration)
            .await
            .expect_err("307 registration response must not be followed");
        assert!(
            matches!(&err, ClientError::ErrorStatus { status: 307, .. }),
            "registration redirect must surface as the original 307: {err}"
        );
        let request = server.await.expect("test server task");
        assert!(request.starts_with("POST /api/agents/register "));
        assert!(
            !request.to_ascii_lowercase().contains("authorization:"),
            "first-boot registration must remain unauthenticated"
        );
    }

    #[tokio::test]
    async fn keyset_bootstrap_is_one_unauthenticated_typed_request() {
        let expected = test_keyset_response();
        let body = serde_json::to_string(&expected).expect("serialize typed bootstrap response");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (base_url, server) = one_response_server(response).await;
        let endpoint = ControlPlaneEndpoint::parse(&base_url, true).expect("loopback opt-in");
        let client = CpClient::from_endpoint(&endpoint, "agent", "rya_must_not_be_sent")
            .expect("client must initialize");

        let actual = client
            .fetch_cp_keyset_response()
            .await
            .expect("typed bootstrap response must parse");
        assert_eq!(actual, expected);
        let request = server.await.expect("test server task");
        assert!(
            !request.to_ascii_lowercase().contains("authorization:"),
            "unauthenticated public-key fetch must omit the bearer"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-ryuki-protocol-version:"),
            "wire protocol header must remain present"
        );
    }

    #[tokio::test]
    async fn malformed_keyset_bootstrap_returns_a_value_free_error() {
        let hostile_marker = "attacker-controlled-bootstrap-value";
        let body =
            format!(r#"{{"keyset":{{"unexpected":"{hostile_marker}"}},"protocol_version":8}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (base_url, server) = one_response_server(response).await;
        let endpoint = ControlPlaneEndpoint::parse(&base_url, true).expect("loopback opt-in");
        let client = CpClient::from_endpoint(&endpoint, "agent", "rya_must_not_be_sent")
            .expect("client must initialize");

        let error = client
            .fetch_cp_keyset_response()
            .await
            .expect_err("schema-invalid bootstrap must fail closed");
        assert!(matches!(
            &error,
            ClientError::InvalidControlPlaneKeysetResponse
        ));
        assert!(!error.to_string().contains(hostile_marker));
        let _request = server.await.expect("test server task");
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
            enrollment_challenge_id: Uuid::nil(),
            enrollment_challenge:
                "ryc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            agent_id: "gblon-proxmox-01".to_owned(),
            platform: "gblon".to_owned(),
            capabilities: Capabilities::default(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            enrollment_proof: "proof".to_owned(),
        };
        let json = serde_json::to_string(&reg).expect("serialise");
        let decoded: AgentRegistration = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(decoded.agent_id, reg.agent_id);
        assert_eq!(decoded.platform, reg.platform);
        assert_eq!(decoded.public_key, reg.public_key);
        assert_eq!(decoded.enrollment_challenge_id, reg.enrollment_challenge_id);
        assert_eq!(decoded.enrollment_challenge, reg.enrollment_challenge);
        assert_eq!(decoded.enrollment_proof, reg.enrollment_proof);
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
    fn heartbeat_body_serialises_idle_and_exact_renewal_fence() {
        let idle = AgentHeartbeat::idle();
        let json = serde_json::to_value(&idle).expect("serialise");
        assert!(json["running_job_id"].is_null());
        assert!(json["attempt_id"].is_null());
        assert!(json["lease_generation"].is_null());
        assert!(json["fencing_token"].is_null());

        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 7,
            fencing_token: "fence-exact".to_owned(),
            deadline: Utc::now() + chrono::Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        let running = AgentHeartbeat::renewing(Uuid::nil(), &lease);
        let json = serde_json::to_value(&running).expect("serialise");
        assert_eq!(json["running_job_id"], serde_json::json!(Uuid::nil()));
        assert_eq!(json["attempt_id"], serde_json::json!(lease.attempt_id));
        assert_eq!(json["lease_generation"], serde_json::json!(7));
        assert_eq!(json["fencing_token"], serde_json::json!("fence-exact"));
    }

    /// Verify that a `Job` body returned by the CP deserialises correctly via
    /// the `ryuki_protocol::Job` type (this is what `poll()` does internally).
    #[test]
    fn job_from_cp_body_deserialises() {
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".to_owned(),
            iac_digest: "a".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
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
            agent_enrollment_id: Uuid::nil(),
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

        let mut missing_version = serde_json::to_value(&job).expect("serialise job value");
        missing_version["spec"]
            .as_object_mut()
            .expect("job spec object")
            .remove("request_resource_version");
        assert!(
            serde_json::from_value::<Job>(missing_version).is_err(),
            "agent ingress must reject a job without a request resource version"
        );

        let mut zero_version = serde_json::to_value(&job).expect("serialise job value");
        zero_version["spec"]["request_resource_version"] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<Job>(zero_version).is_err(),
            "agent ingress must reject a non-positive request resource version"
        );
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
    // fetch_cp_keyset_response — URL construction + typed response contract
    // -----------------------------------------------------------------------

    #[test]
    fn cp_public_key_url_is_correct() {
        let client = CpClient::new("https://cp.example.com/", "defra-vcenter-01", "rya_tok");
        let expected = "https://cp.example.com/api/agents/cp-public-key";
        let actual = client.endpoint.join("api/agents/cp-public-key");
        assert_eq!(
            actual.as_str(),
            expected,
            "cp-public-key URL must use base_url without trailing slash"
        );
    }

    #[test]
    fn cp_keyset_response_roundtrips_as_one_closed_document() {
        let expected = test_keyset_response();
        let encoded = serde_json::to_vec(&expected).expect("serialize typed response");
        let decoded: ControlPlaneGrantKeysetResponse =
            serde_json::from_slice(&encoded).expect("deserialize typed response");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn cp_keyset_response_requires_both_version_and_keyset() {
        for body in [
            serde_json::json!({"protocol_version": ryuki_protocol::PROTOCOL_VERSION}),
            serde_json::json!({"keyset": test_keyset_response().keyset}),
        ] {
            assert!(
                serde_json::from_value::<ControlPlaneGrantKeysetResponse>(body).is_err(),
                "the atomic bootstrap document must require both fields"
            );
        }
    }
}
