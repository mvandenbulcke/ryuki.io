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
use std::io;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::path::{Component, Path};
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::time::timeout;

/// Conservative cross-Unix pathname limit, excluding the terminating NUL byte.
///
/// Darwin exposes a 104-byte `sun_path`; Linux exposes 108 bytes. Keeping the complete path at
/// or below 103 bytes makes the same configured endpoint safe on both supported families.
#[cfg(unix)]
pub(crate) const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
pub(crate) const MAX_CHECKPOINT_REQUEST_BYTES: usize = 16 * 1024;
pub(crate) const MAX_CHECKPOINT_RESPONSE_BYTES: usize = 256 * 1024;
#[cfg(unix)]
pub(crate) const MAX_CHECKPOINT_PHASE_DEADLINE: Duration = Duration::from_secs(30);

#[cfg(unix)]
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
    socket_path: PathBuf,
    deadlines: TrustCheckpointTransportDeadlines,
    bounds: TrustCheckpointTransportBounds,
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
            validate_socket_path(&socket_path)?;
            validate_deadlines(deadlines)?;
            validate_bounds(bounds)?;

            Ok(Self {
                socket_path,
                deadlines,
                bounds,
            })
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
            if request_bytes.is_empty() {
                return Err(TrustCheckpointTransportError::EmptyRequest);
            }
            if request_bytes.len() > self.bounds.max_request_bytes {
                return Err(TrustCheckpointTransportError::RequestTooLarge {
                    actual: request_bytes.len(),
                    limit: self.bounds.max_request_bytes,
                });
            }

            let request_length = u32::try_from(request_bytes.len()).map_err(|_| {
                TrustCheckpointTransportError::RequestTooLarge {
                    actual: request_bytes.len(),
                    limit: self.bounds.max_request_bytes,
                }
            })?;

            let mut stream = timeout(
                self.deadlines.connect,
                UnixStream::connect(&self.socket_path),
            )
            .await
            .map_err(|_| TrustCheckpointTransportError::ConnectTimedOut {
                deadline: self.deadlines.connect,
            })?
            .map_err(|source| TrustCheckpointTransportError::ConnectFailed { source })?;

            timeout(self.deadlines.write, async {
                stream.write_all(&request_length.to_be_bytes()).await?;
                stream.write_all(request_bytes).await?;
                stream.shutdown().await
            })
            .await
            .map_err(|_| TrustCheckpointTransportError::WriteTimedOut {
                deadline: self.deadlines.write,
            })?
            .map_err(|source| TrustCheckpointTransportError::WriteFailed { source })?;

            timeout(
                self.deadlines.read,
                read_single_response_frame(&mut stream, self.bounds.max_response_bytes),
            )
            .await
            .map_err(|_| TrustCheckpointTransportError::ReadTimedOut {
                deadline: self.deadlines.read,
            })?
        }
    }
}

#[cfg(unix)]
fn validate_socket_path(path: &Path) -> Result<(), TrustCheckpointTransportError> {
    if !path.is_absolute() {
        return Err(TrustCheckpointTransportError::SocketPathNotAbsolute);
    }
    if path.file_name().is_none() {
        return Err(TrustCheckpointTransportError::SocketPathMissingFileName);
    }

    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(TrustCheckpointTransportError::SocketPathNotNormalized);
            }
        }
    }

    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.contains(&0) {
        return Err(TrustCheckpointTransportError::SocketPathContainsNul);
    }
    if normalized.as_os_str().as_bytes() != path_bytes {
        return Err(TrustCheckpointTransportError::SocketPathNotNormalized);
    }
    if path_bytes.len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(TrustCheckpointTransportError::SocketPathTooLong {
            actual: path_bytes.len(),
            limit: MAX_UNIX_SOCKET_PATH_BYTES,
        });
    }

    Ok(())
}

#[cfg(unix)]
fn validate_deadlines(
    deadlines: TrustCheckpointTransportDeadlines,
) -> Result<(), TrustCheckpointTransportError> {
    for (phase, deadline) in [
        (TrustCheckpointDeadlinePhase::Connect, deadlines.connect),
        (TrustCheckpointDeadlinePhase::Write, deadlines.write),
        (TrustCheckpointDeadlinePhase::Read, deadlines.read),
    ] {
        if deadline.is_zero() {
            return Err(TrustCheckpointTransportError::InvalidDeadline { phase });
        }
        if deadline > MAX_CHECKPOINT_PHASE_DEADLINE {
            return Err(TrustCheckpointTransportError::DeadlineTooLong {
                phase,
                configured: deadline,
                hard_limit: MAX_CHECKPOINT_PHASE_DEADLINE,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_bounds(
    bounds: TrustCheckpointTransportBounds,
) -> Result<(), TrustCheckpointTransportError> {
    for (bound, configured, hard_limit) in [
        (
            "request",
            bounds.max_request_bytes,
            MAX_CHECKPOINT_REQUEST_BYTES,
        ),
        (
            "response",
            bounds.max_response_bytes,
            MAX_CHECKPOINT_RESPONSE_BYTES,
        ),
    ] {
        if configured == 0 || configured > hard_limit {
            return Err(TrustCheckpointTransportError::InvalidBound {
                bound,
                configured,
                hard_limit,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn read_single_response_frame(
    stream: &mut UnixStream,
    max_response_bytes: usize,
) -> Result<Vec<u8>, TrustCheckpointTransportError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let header_bytes = read_exact_count(stream, &mut header)
        .await
        .map_err(|source| TrustCheckpointTransportError::ReadFailed {
            phase: TrustCheckpointReadPhase::Header,
            source,
        })?;
    if header_bytes != FRAME_HEADER_BYTES {
        return Err(TrustCheckpointTransportError::TruncatedHeader {
            expected: FRAME_HEADER_BYTES,
            received: header_bytes,
        });
    }

    let declared = u32::from_be_bytes(header) as usize;
    if declared == 0 {
        return Err(TrustCheckpointTransportError::EmptyResponse);
    }
    if declared > max_response_bytes {
        return Err(TrustCheckpointTransportError::ResponseTooLarge {
            declared,
            limit: max_response_bytes,
        });
    }

    let mut response = vec![0_u8; declared];
    let body_bytes = read_exact_count(stream, &mut response)
        .await
        .map_err(|source| TrustCheckpointTransportError::ReadFailed {
            phase: TrustCheckpointReadPhase::Body,
            source,
        })?;
    if body_bytes != declared {
        return Err(TrustCheckpointTransportError::TruncatedResponse {
            declared,
            received: body_bytes,
        });
    }

    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing).await {
        Ok(0) => Ok(response),
        Ok(_) => Err(TrustCheckpointTransportError::TrailingResponseBytes),
        Err(source) => Err(TrustCheckpointTransportError::ReadFailed {
            phase: TrustCheckpointReadPhase::EndOfFrame,
            source,
        }),
    }
}

#[cfg(unix)]
async fn read_exact_count<R: AsyncRead + Unpin>(
    reader: &mut R,
    destination: &mut [u8],
) -> io::Result<usize> {
    let mut received = 0;
    while received < destination.len() {
        let read = reader.read(&mut destination[received..]).await?;
        if read == 0 {
            break;
        }
        received += read;
    }
    Ok(received)
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
    use tokio::net::UnixListener;
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
