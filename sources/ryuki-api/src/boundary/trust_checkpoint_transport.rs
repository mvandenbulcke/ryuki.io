//! Bounded transport for the independently operated conformance checkpoint authority.
//!
//! This adapter deliberately has no bootstrap, mutation, or local fallback API. It performs
//! exactly one opaque read/reconcile request-response exchange per Unix-domain-socket
//! connection. The response bytes are untrusted transport output; callers must authenticate
//! and validate them with the pure `ryuki-core` checkpoint verifier before using them.

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

#[cfg(unix)]
use super::authority_transport::{
    AuthorityDeadlinePhase, AuthorityReadPhase, AuthorityTransportBounds,
    AuthorityTransportDeadlines, AuthorityTransportError, AuthorityTransportHardLimits,
    UnixAuthorityTransport,
};

#[cfg(unix)]
use std::io;

/// Conservative cross-Unix pathname limit, excluding the terminating NUL byte.
///
/// Darwin exposes a 104-byte `sun_path`; Linux exposes 108 bytes. Keeping the complete path at
/// or below 103 bytes makes the same configured endpoint safe on both supported families.
#[cfg(unix)]
pub(crate) const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
pub(crate) const MAX_CHECKPOINT_REQUEST_BYTES: usize = 512 * 1024;
pub(crate) const MAX_CHECKPOINT_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
#[cfg(unix)]
pub(crate) const MAX_CHECKPOINT_PHASE_DEADLINE: Duration = Duration::from_secs(30);

#[cfg(all(test, unix))]
const FRAME_HEADER_BYTES: usize = std::mem::size_of::<u32>();

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustCheckpointTransportBounds {
    max_request_bytes: usize,
    max_response_bytes: usize,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustCheckpointTransportBounds;

impl TrustCheckpointTransportBounds {
    pub(crate) const fn new(max_request_bytes: usize, max_response_bytes: usize) -> Self {
        #[cfg(unix)]
        {
            Self {
                max_request_bytes,
                max_response_bytes,
            }
        }

        #[cfg(not(unix))]
        {
            let _ = (max_request_bytes, max_response_bytes);
            Self
        }
    }

    pub(crate) const fn production() -> Self {
        Self::new(MAX_CHECKPOINT_REQUEST_BYTES, MAX_CHECKPOINT_RESPONSE_BYTES)
    }
}

impl Default for TrustCheckpointTransportBounds {
    fn default() -> Self {
        Self::production()
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustCheckpointTransportDeadlines {
    connect: Duration,
    write: Duration,
    read: Duration,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustCheckpointTransportDeadlines;

impl TrustCheckpointTransportDeadlines {
    const fn uniform(deadline: Duration) -> Self {
        #[cfg(unix)]
        {
            Self {
                connect: deadline,
                write: deadline,
                read: deadline,
            }
        }

        #[cfg(not(unix))]
        {
            let _ = deadline;
            Self
        }
    }

    #[cfg(all(test, unix))]
    const fn new(connect: Duration, write: Duration, read: Duration) -> Self {
        Self {
            connect,
            write,
            read,
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustCheckpointDeadlinePhase {
    Connect,
    Write,
    Read,
}

#[cfg(unix)]
impl std::fmt::Display for TrustCheckpointDeadlinePhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => formatter.write_str("connect"),
            Self::Write => formatter.write_str("write"),
            Self::Read => formatter.write_str("read"),
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustCheckpointReadPhase {
    Header,
    Body,
    EndOfFrame,
}

#[cfg(unix)]
impl std::fmt::Display for TrustCheckpointReadPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header => formatter.write_str("frame header"),
            Self::Body => formatter.write_str("frame body"),
            Self::EndOfFrame => formatter.write_str("end of frame"),
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Error)]
pub(crate) enum TrustCheckpointTransportError {
    #[error("conformance checkpoint socket path must be absolute")]
    SocketPathNotAbsolute,
    #[error("conformance checkpoint socket path must name a socket, not the filesystem root")]
    SocketPathMissingFileName,
    #[error("conformance checkpoint socket path must be lexically normalized")]
    SocketPathNotNormalized,
    #[error("conformance checkpoint socket path contains a NUL byte")]
    SocketPathContainsNul,
    #[error(
        "conformance checkpoint socket path is {actual} bytes, exceeding the {limit}-byte limit"
    )]
    SocketPathTooLong { actual: usize, limit: usize },
    #[error("conformance checkpoint {phase} deadline must be greater than zero")]
    InvalidDeadline { phase: TrustCheckpointDeadlinePhase },
    #[error(
        "conformance checkpoint {phase} deadline {configured:?} exceeds the {hard_limit:?} hard limit"
    )]
    DeadlineTooLong {
        phase: TrustCheckpointDeadlinePhase,
        configured: Duration,
        hard_limit: Duration,
    },
    #[error(
        "conformance checkpoint {bound} bound must be between 1 and {hard_limit} bytes (got {configured})"
    )]
    InvalidBound {
        bound: &'static str,
        configured: usize,
        hard_limit: usize,
    },
    #[error("conformance checkpoint reconciliation request must not be empty")]
    EmptyRequest,
    #[error(
        "conformance checkpoint reconciliation request is {actual} bytes, exceeding the configured {limit}-byte limit"
    )]
    RequestTooLarge { actual: usize, limit: usize },
    #[error("conformance checkpoint authority connect timed out after {deadline:?}")]
    ConnectTimedOut { deadline: Duration },
    #[error("conformance checkpoint authority connection failed: {source}")]
    ConnectFailed {
        #[source]
        source: io::Error,
    },
    #[error("conformance checkpoint request write timed out after {deadline:?}")]
    WriteTimedOut { deadline: Duration },
    #[error("conformance checkpoint request write failed: {source}")]
    WriteFailed {
        #[source]
        source: io::Error,
    },
    #[error("conformance checkpoint response read timed out after {deadline:?}")]
    ReadTimedOut { deadline: Duration },
    #[error("conformance checkpoint response {phase} read failed: {source}")]
    ReadFailed {
        phase: TrustCheckpointReadPhase,
        #[source]
        source: io::Error,
    },
    #[error(
        "conformance checkpoint response frame header was truncated: expected {expected} bytes, received {received}"
    )]
    TruncatedHeader { expected: usize, received: usize },
    #[error("conformance checkpoint response frame declared an empty body")]
    EmptyResponse,
    #[error(
        "conformance checkpoint response declares {declared} bytes, exceeding the configured {limit}-byte limit"
    )]
    ResponseTooLarge { declared: usize, limit: usize },
    #[error(
        "conformance checkpoint response frame was truncated: declared {declared} bytes, received {received}"
    )]
    TruncatedResponse { declared: usize, received: usize },
    #[error("conformance checkpoint authority sent bytes after the declared response frame")]
    TrailingResponseBytes,
}

#[cfg(not(unix))]
#[derive(Debug, Error)]
pub(crate) enum TrustCheckpointTransportError {
    #[error("conformance checkpoint authority transport is unsupported on this platform")]
    UnsupportedPlatform,
}

/// Read/reconcile-only client for an independently operated checkpoint authority.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct UnixTrustCheckpointTransport {
    inner: UnixAuthorityTransport,
}

/// Uninhabited transport on targets that cannot provide the required Unix socket boundary.
#[cfg(not(unix))]
#[derive(Debug, Clone)]
pub(crate) enum UnixTrustCheckpointTransport {}

impl UnixTrustCheckpointTransport {
    /// Constructs a transport with the same independent deadline for connect, write, and read.
    pub(crate) fn new(
        socket_path: PathBuf,
        deadline: Duration,
        bounds: TrustCheckpointTransportBounds,
    ) -> Result<Self, TrustCheckpointTransportError> {
        Self::with_deadlines(
            socket_path,
            TrustCheckpointTransportDeadlines::uniform(deadline),
            bounds,
        )
    }

    fn with_deadlines(
        socket_path: PathBuf,
        deadlines: TrustCheckpointTransportDeadlines,
        bounds: TrustCheckpointTransportBounds,
    ) -> Result<Self, TrustCheckpointTransportError> {
        #[cfg(not(unix))]
        {
            let _ = (socket_path, deadlines, bounds);
            Err(TrustCheckpointTransportError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            let inner = UnixAuthorityTransport::new(
                socket_path,
                AuthorityTransportDeadlines {
                    connect: deadlines.connect,
                    write: deadlines.write,
                    read: deadlines.read,
                },
                AuthorityTransportBounds {
                    max_request_bytes: bounds.max_request_bytes,
                    max_response_bytes: bounds.max_response_bytes,
                },
                AuthorityTransportHardLimits {
                    max_socket_path_bytes: MAX_UNIX_SOCKET_PATH_BYTES,
                    max_phase_deadline: MAX_CHECKPOINT_PHASE_DEADLINE,
                    max_request_bytes: MAX_CHECKPOINT_REQUEST_BYTES,
                    max_response_bytes: MAX_CHECKPOINT_RESPONSE_BYTES,
                },
            )
            .map_err(map_authority_transport_error)?;
            Ok(Self { inner })
        }
    }

    /// Exchanges one opaque reconciliation request for one opaque, untrusted response.
    ///
    /// Framing is exactly a four-byte unsigned big-endian length followed by that many payload
    /// bytes. The authority must close its write side after its single response frame; extra
    /// bytes and a connection left open past the read deadline both fail closed. This layer never
    /// retries: a caller that deliberately retries must obtain a fresh core request and nonce.
    pub(crate) async fn read_reconcile(
        &self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, TrustCheckpointTransportError> {
        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            Err(TrustCheckpointTransportError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            self.inner
                .exchange(request_bytes)
                .await
                .map_err(map_authority_transport_error)
        }
    }
}

#[cfg(unix)]
fn map_authority_transport_error(error: AuthorityTransportError) -> TrustCheckpointTransportError {
    match error {
        AuthorityTransportError::SocketPathNotAbsolute => {
            TrustCheckpointTransportError::SocketPathNotAbsolute
        }
        AuthorityTransportError::SocketPathMissingFileName => {
            TrustCheckpointTransportError::SocketPathMissingFileName
        }
        AuthorityTransportError::SocketPathNotNormalized => {
            TrustCheckpointTransportError::SocketPathNotNormalized
        }
        AuthorityTransportError::SocketPathContainsNul => {
            TrustCheckpointTransportError::SocketPathContainsNul
        }
        AuthorityTransportError::SocketPathTooLong { actual, limit } => {
            TrustCheckpointTransportError::SocketPathTooLong { actual, limit }
        }
        AuthorityTransportError::InvalidDeadline { phase } => {
            TrustCheckpointTransportError::InvalidDeadline {
                phase: map_deadline_phase(phase),
            }
        }
        AuthorityTransportError::DeadlineTooLong {
            phase,
            configured,
            hard_limit,
        } => TrustCheckpointTransportError::DeadlineTooLong {
            phase: map_deadline_phase(phase),
            configured,
            hard_limit,
        },
        AuthorityTransportError::InvalidBound {
            bound,
            configured,
            hard_limit,
        } => TrustCheckpointTransportError::InvalidBound {
            bound,
            configured,
            hard_limit,
        },
        AuthorityTransportError::EmptyRequest => TrustCheckpointTransportError::EmptyRequest,
        AuthorityTransportError::RequestTooLarge { actual, limit } => {
            TrustCheckpointTransportError::RequestTooLarge { actual, limit }
        }
        AuthorityTransportError::ConnectTimedOut { deadline } => {
            TrustCheckpointTransportError::ConnectTimedOut { deadline }
        }
        AuthorityTransportError::ConnectFailed { source } => {
            TrustCheckpointTransportError::ConnectFailed { source }
        }
        AuthorityTransportError::WriteTimedOut { deadline } => {
            TrustCheckpointTransportError::WriteTimedOut { deadline }
        }
        AuthorityTransportError::WriteFailed { source } => {
            TrustCheckpointTransportError::WriteFailed { source }
        }
        AuthorityTransportError::ReadTimedOut { deadline } => {
            TrustCheckpointTransportError::ReadTimedOut { deadline }
        }
        AuthorityTransportError::ReadFailed { phase, source } => {
            TrustCheckpointTransportError::ReadFailed {
                phase: map_read_phase(phase),
                source,
            }
        }
        AuthorityTransportError::TruncatedHeader { expected, received } => {
            TrustCheckpointTransportError::TruncatedHeader { expected, received }
        }
        AuthorityTransportError::EmptyResponse => TrustCheckpointTransportError::EmptyResponse,
        AuthorityTransportError::ResponseTooLarge { declared, limit } => {
            TrustCheckpointTransportError::ResponseTooLarge { declared, limit }
        }
        AuthorityTransportError::TruncatedResponse { declared, received } => {
            TrustCheckpointTransportError::TruncatedResponse { declared, received }
        }
        AuthorityTransportError::TrailingResponseBytes => {
            TrustCheckpointTransportError::TrailingResponseBytes
        }
    }
}

#[cfg(unix)]
const fn map_deadline_phase(phase: AuthorityDeadlinePhase) -> TrustCheckpointDeadlinePhase {
    match phase {
        AuthorityDeadlinePhase::Connect => TrustCheckpointDeadlinePhase::Connect,
        AuthorityDeadlinePhase::Write => TrustCheckpointDeadlinePhase::Write,
        AuthorityDeadlinePhase::Read => TrustCheckpointDeadlinePhase::Read,
    }
}

#[cfg(unix)]
const fn map_read_phase(phase: AuthorityReadPhase) -> TrustCheckpointReadPhase {
    match phase {
        AuthorityReadPhase::Header => TrustCheckpointReadPhase::Header,
        AuthorityReadPhase::Body => TrustCheckpointReadPhase::Body,
        AuthorityReadPhase::EndOfFrame => TrustCheckpointReadPhase::EndOfFrame,
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn checkpoint_transport_is_unavailable_without_unix_sockets() {
        assert!(matches!(
            UnixTrustCheckpointTransport::new(
                PathBuf::from("checkpoint-authority.sock"),
                Duration::from_secs(1),
                TrustCheckpointTransportBounds::default(),
            ),
            Err(TrustCheckpointTransportError::UnsupportedPlatform)
        ));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::{Builder, TempDir};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::task::JoinHandle;

    const TEST_DEADLINE: Duration = Duration::from_secs(2);

    fn socket_fixture() -> (TempDir, PathBuf, UnixListener) {
        let directory = Builder::new()
            .prefix("ryuki-ckpt-")
            .tempdir_in("/tmp")
            .expect("create short socket test directory");
        let socket_path = directory.path().join("authority.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind fake checkpoint authority");
        (directory, socket_path, listener)
    }

    fn transport(
        socket_path: PathBuf,
        deadline: Duration,
        response_limit: usize,
    ) -> UnixTrustCheckpointTransport {
        UnixTrustCheckpointTransport::new(
            socket_path,
            deadline,
            TrustCheckpointTransportBounds::new(1024, response_limit),
        )
        .expect("construct checkpoint transport")
    }

    async fn read_request(stream: &mut UnixStream) -> Vec<u8> {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        stream
            .read_exact(&mut header)
            .await
            .expect("read request header");
        let length = u32::from_be_bytes(header) as usize;
        let mut request = vec![0_u8; length];
        stream
            .read_exact(&mut request)
            .await
            .expect("read request body");
        request
    }

    fn spawn_authority<F, Fut>(listener: UnixListener, handler: F) -> JoinHandle<()>
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept transport client");
            handler(stream).await;
        })
    }

    #[tokio::test]
    async fn read_reconcile_exchanges_exact_length_delimited_bytes() {
        let (_directory, socket_path, listener) = socket_fixture();
        let request = br#"{"operation":"read_reconcile"}"#.to_vec();
        let response = br#"{"outcome":"matched","signature_base64":"opaque"}"#.to_vec();
        let expected_request = request.clone();
        let server_response = response.clone();
        let server = spawn_authority(listener, move |mut stream| async move {
            assert_eq!(read_request(&mut stream).await, expected_request);
            stream
                .write_all(&(server_response.len() as u32).to_be_bytes())
                .await
                .expect("write response header");
            stream
                .write_all(&server_response)
                .await
                .expect("write response body");
            stream.shutdown().await.expect("close response write side");
        });

        let actual = transport(socket_path, TEST_DEADLINE, 1024)
            .read_reconcile(&request)
            .await
            .expect("read opaque authority response");

        assert_eq!(actual, response);
        server.await.expect("fake authority task succeeds");
    }

    #[tokio::test]
    async fn truncated_response_is_classified_with_exact_byte_counts() {
        let (_directory, socket_path, listener) = socket_fixture();
        let server = spawn_authority(listener, |mut stream| async move {
            let _ = read_request(&mut stream).await;
            stream
                .write_all(&8_u32.to_be_bytes())
                .await
                .expect("write declared response length");
            stream
                .write_all(b"abc")
                .await
                .expect("write partial response");
            stream.shutdown().await.expect("truncate response");
        });

        let error = transport(socket_path, TEST_DEADLINE, 1024)
            .read_reconcile(b"request")
            .await
            .expect_err("truncated authority response must fail");

        assert!(matches!(
            error,
            TrustCheckpointTransportError::TruncatedResponse {
                declared: 8,
                received: 3
            }
        ));
        server.await.expect("fake authority task succeeds");
    }

    #[tokio::test]
    async fn oversized_declared_response_is_rejected_before_body_read() {
        let (_directory, socket_path, listener) = socket_fixture();
        let server = spawn_authority(listener, |mut stream| async move {
            let _ = read_request(&mut stream).await;
            stream
                .write_all(&65_u32.to_be_bytes())
                .await
                .expect("write oversized response declaration");
            stream.shutdown().await.expect("close fake response");
        });

        let error = transport(socket_path, TEST_DEADLINE, 64)
            .read_reconcile(b"request")
            .await
            .expect_err("oversized authority response must fail");

        assert!(matches!(
            error,
            TrustCheckpointTransportError::ResponseTooLarge {
                declared: 65,
                limit: 64
            }
        ));
        server.await.expect("fake authority task succeeds");
    }

    #[tokio::test]
    async fn stalled_authority_hits_the_absolute_read_deadline() {
        let (_directory, socket_path, listener) = socket_fixture();
        let server = spawn_authority(listener, |mut stream| async move {
            let _ = read_request(&mut stream).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        });

        let transport = UnixTrustCheckpointTransport::with_deadlines(
            socket_path,
            TrustCheckpointTransportDeadlines::new(
                TEST_DEADLINE,
                TEST_DEADLINE,
                Duration::from_millis(30),
            ),
            TrustCheckpointTransportBounds::new(1024, 1024),
        )
        .expect("construct transport with an independent read deadline");
        let error = transport
            .read_reconcile(b"request")
            .await
            .expect_err("stalled authority must time out");

        assert!(matches!(
            error,
            TrustCheckpointTransportError::ReadTimedOut { .. }
        ));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn trailing_response_bytes_are_rejected() {
        let (_directory, socket_path, listener) = socket_fixture();
        let server = spawn_authority(listener, |mut stream| async move {
            let _ = read_request(&mut stream).await;
            stream
                .write_all(&3_u32.to_be_bytes())
                .await
                .expect("write response header");
            stream
                .write_all(b"okay")
                .await
                .expect("write framed body plus trailing byte");
            stream.shutdown().await.expect("close response");
        });

        let error = transport(socket_path, TEST_DEADLINE, 1024)
            .read_reconcile(b"request")
            .await
            .expect_err("trailing authority bytes must fail");
        assert!(matches!(
            error,
            TrustCheckpointTransportError::TrailingResponseBytes
        ));
        server.await.expect("fake authority task succeeds");
    }

    #[test]
    fn socket_paths_must_be_absolute_normalized_and_bounded() {
        let bounds = TrustCheckpointTransportBounds::default();

        assert!(matches!(
            UnixTrustCheckpointTransport::new(
                PathBuf::from("authority.sock"),
                TEST_DEADLINE,
                bounds
            ),
            Err(TrustCheckpointTransportError::SocketPathNotAbsolute)
        ));
        assert!(matches!(
            UnixTrustCheckpointTransport::new(
                PathBuf::from("/tmp/../authority.sock"),
                TEST_DEADLINE,
                bounds
            ),
            Err(TrustCheckpointTransportError::SocketPathNotNormalized)
        ));
        assert!(matches!(
            UnixTrustCheckpointTransport::new(PathBuf::from("/"), TEST_DEADLINE, bounds),
            Err(TrustCheckpointTransportError::SocketPathMissingFileName)
        ));

        let too_long = PathBuf::from(format!("/tmp/{}.sock", "a".repeat(100)));
        assert!(matches!(
            UnixTrustCheckpointTransport::new(too_long, TEST_DEADLINE, bounds),
            Err(TrustCheckpointTransportError::SocketPathTooLong { .. })
        ));
    }

    #[test]
    fn zero_deadlines_and_unbounded_configurations_fail_at_construction() {
        let path = PathBuf::from("/tmp/checkpoint.sock");
        assert!(matches!(
            UnixTrustCheckpointTransport::new(
                path.clone(),
                Duration::ZERO,
                TrustCheckpointTransportBounds::default()
            ),
            Err(TrustCheckpointTransportError::InvalidDeadline {
                phase: TrustCheckpointDeadlinePhase::Connect
            })
        ));
        assert!(matches!(
            UnixTrustCheckpointTransport::new(
                path.clone(),
                MAX_CHECKPOINT_PHASE_DEADLINE + Duration::from_nanos(1),
                TrustCheckpointTransportBounds::default()
            ),
            Err(TrustCheckpointTransportError::DeadlineTooLong {
                phase: TrustCheckpointDeadlinePhase::Connect,
                ..
            })
        ));
        assert!(matches!(
            UnixTrustCheckpointTransport::new(
                path,
                TEST_DEADLINE,
                TrustCheckpointTransportBounds::new(
                    MAX_CHECKPOINT_REQUEST_BYTES + 1,
                    MAX_CHECKPOINT_RESPONSE_BYTES
                )
            ),
            Err(TrustCheckpointTransportError::InvalidBound {
                bound: "request",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn empty_and_oversized_requests_never_connect() {
        let (_directory, socket_path, _listener) = socket_fixture();
        let transport = UnixTrustCheckpointTransport::new(
            socket_path,
            TEST_DEADLINE,
            TrustCheckpointTransportBounds::new(4, 1024),
        )
        .expect("construct bounded transport");

        assert!(matches!(
            transport.read_reconcile(b"").await,
            Err(TrustCheckpointTransportError::EmptyRequest)
        ));
        assert!(matches!(
            transport.read_reconcile(b"12345").await,
            Err(TrustCheckpointTransportError::RequestTooLarge {
                actual: 5,
                limit: 4
            })
        ));
    }

    #[tokio::test]
    async fn missing_socket_is_a_connect_failure_without_fallback() {
        let directory = Builder::new()
            .prefix("ryuki-ckpt-")
            .tempdir_in("/tmp")
            .expect("create short socket test directory");
        let socket_path = directory.path().join("missing.sock");

        let error = transport(socket_path, TEST_DEADLINE, 1024)
            .read_reconcile(b"request")
            .await
            .expect_err("missing socket must fail closed");

        assert!(matches!(
            error,
            TrustCheckpointTransportError::ConnectFailed { .. }
        ));
    }
}
