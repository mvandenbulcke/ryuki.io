//! Semantic-neutral, bounded one-shot transport for local authority services.
//!
//! The transport exchanges exactly one length-delimited request and response on
//! one Unix-domain-socket connection. It performs no retries, authentication,
//! protocol interpretation, mutation, bootstrap, or fallback.

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

#[cfg(unix)]
const FRAME_HEADER_BYTES: usize = std::mem::size_of::<u32>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityTransportBounds {
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityTransportDeadlines {
    pub(crate) connect: Duration,
    pub(crate) write: Duration,
    pub(crate) read: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityTransportHardLimits {
    pub(crate) max_socket_path_bytes: usize,
    pub(crate) max_phase_deadline: Duration,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityDeadlinePhase {
    Connect,
    Write,
    Read,
}

impl std::fmt::Display for AuthorityDeadlinePhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => formatter.write_str("connect"),
            Self::Write => formatter.write_str("write"),
            Self::Read => formatter.write_str("read"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityReadPhase {
    Header,
    Body,
    EndOfFrame,
}

impl std::fmt::Display for AuthorityReadPhase {
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
pub(crate) enum AuthorityTransportError {
    #[error("authority socket path must be absolute")]
    SocketPathNotAbsolute,
    #[error("authority socket path must name a socket, not the filesystem root")]
    SocketPathMissingFileName,
    #[error("authority socket path must be lexically normalized")]
    SocketPathNotNormalized,
    #[error("authority socket path contains a NUL byte")]
    SocketPathContainsNul,
    #[error("authority socket path is {actual} bytes, exceeding the {limit}-byte limit")]
    SocketPathTooLong { actual: usize, limit: usize },
    #[error("authority {phase} deadline must be greater than zero")]
    InvalidDeadline { phase: AuthorityDeadlinePhase },
    #[error("authority {phase} deadline {configured:?} exceeds the {hard_limit:?} hard limit")]
    DeadlineTooLong {
        phase: AuthorityDeadlinePhase,
        configured: Duration,
        hard_limit: Duration,
    },
    #[error("authority {bound} bound must be between 1 and {hard_limit} bytes (got {configured})")]
    InvalidBound {
        bound: &'static str,
        configured: usize,
        hard_limit: usize,
    },
    #[error("authority request must not be empty")]
    EmptyRequest,
    #[error("authority request is {actual} bytes, exceeding the configured {limit}-byte limit")]
    RequestTooLarge { actual: usize, limit: usize },
    #[error("authority connect timed out after {deadline:?}")]
    ConnectTimedOut { deadline: Duration },
    #[error("authority connection failed: {source}")]
    ConnectFailed {
        #[source]
        source: io::Error,
    },
    #[error("authority request write timed out after {deadline:?}")]
    WriteTimedOut { deadline: Duration },
    #[error("authority request write failed: {source}")]
    WriteFailed {
        #[source]
        source: io::Error,
    },
    #[error("authority response read timed out after {deadline:?}")]
    ReadTimedOut { deadline: Duration },
    #[error("authority response {phase} read failed: {source}")]
    ReadFailed {
        phase: AuthorityReadPhase,
        #[source]
        source: io::Error,
    },
    #[error(
        "authority response frame header was truncated: expected {expected} bytes, received {received}"
    )]
    TruncatedHeader { expected: usize, received: usize },
    #[error("authority response frame declared an empty body")]
    EmptyResponse,
    #[error(
        "authority response declares {declared} bytes, exceeding the configured {limit}-byte limit"
    )]
    ResponseTooLarge { declared: usize, limit: usize },
    #[error(
        "authority response frame was truncated: declared {declared} bytes, received {received}"
    )]
    TruncatedResponse { declared: usize, received: usize },
    #[error("authority sent bytes after the declared response frame")]
    TrailingResponseBytes,
}

#[cfg(not(unix))]
#[derive(Debug, Error)]
pub(crate) enum AuthorityTransportError {
    #[error("authority transport is unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct UnixAuthorityTransport {
    socket_path: PathBuf,
    deadlines: AuthorityTransportDeadlines,
    bounds: AuthorityTransportBounds,
}

#[cfg(not(unix))]
#[derive(Debug, Clone)]
pub(crate) enum UnixAuthorityTransport {}

impl UnixAuthorityTransport {
    pub(crate) fn new(
        socket_path: PathBuf,
        deadlines: AuthorityTransportDeadlines,
        bounds: AuthorityTransportBounds,
        hard_limits: AuthorityTransportHardLimits,
    ) -> Result<Self, AuthorityTransportError> {
        #[cfg(not(unix))]
        {
            let _ = (socket_path, deadlines, bounds, hard_limits);
            Err(AuthorityTransportError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            validate_socket_path(&socket_path, hard_limits.max_socket_path_bytes)?;
            validate_deadlines(deadlines, hard_limits.max_phase_deadline)?;
            validate_bounds(bounds, hard_limits)?;
            Ok(Self {
                socket_path,
                deadlines,
                bounds,
            })
        }
    }

    /// Performs one request/response exchange on one connection, without retry.
    pub(crate) async fn exchange(
        &self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, AuthorityTransportError> {
        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            Err(AuthorityTransportError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            if request_bytes.is_empty() {
                return Err(AuthorityTransportError::EmptyRequest);
            }
            if request_bytes.len() > self.bounds.max_request_bytes {
                return Err(AuthorityTransportError::RequestTooLarge {
                    actual: request_bytes.len(),
                    limit: self.bounds.max_request_bytes,
                });
            }
            let request_length = u32::try_from(request_bytes.len()).map_err(|_| {
                AuthorityTransportError::RequestTooLarge {
                    actual: request_bytes.len(),
                    limit: self.bounds.max_request_bytes,
                }
            })?;

            let mut stream = timeout(
                self.deadlines.connect,
                UnixStream::connect(&self.socket_path),
            )
            .await
            .map_err(|_| AuthorityTransportError::ConnectTimedOut {
                deadline: self.deadlines.connect,
            })?
            .map_err(|source| AuthorityTransportError::ConnectFailed { source })?;

            timeout(self.deadlines.write, async {
                stream.write_all(&request_length.to_be_bytes()).await?;
                stream.write_all(request_bytes).await?;
                stream.shutdown().await
            })
            .await
            .map_err(|_| AuthorityTransportError::WriteTimedOut {
                deadline: self.deadlines.write,
            })?
            .map_err(|source| AuthorityTransportError::WriteFailed { source })?;

            timeout(
                self.deadlines.read,
                read_single_response_frame(&mut stream, self.bounds.max_response_bytes),
            )
            .await
            .map_err(|_| AuthorityTransportError::ReadTimedOut {
                deadline: self.deadlines.read,
            })?
        }
    }
}

#[cfg(unix)]
fn validate_socket_path(path: &Path, limit: usize) -> Result<(), AuthorityTransportError> {
    if !path.is_absolute() {
        return Err(AuthorityTransportError::SocketPathNotAbsolute);
    }
    if path.file_name().is_none() {
        return Err(AuthorityTransportError::SocketPathMissingFileName);
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(AuthorityTransportError::SocketPathNotNormalized);
            }
        }
    }
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.contains(&0) {
        return Err(AuthorityTransportError::SocketPathContainsNul);
    }
    if normalized.as_os_str().as_bytes() != path_bytes {
        return Err(AuthorityTransportError::SocketPathNotNormalized);
    }
    if path_bytes.len() > limit {
        return Err(AuthorityTransportError::SocketPathTooLong {
            actual: path_bytes.len(),
            limit,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_deadlines(
    deadlines: AuthorityTransportDeadlines,
    hard_limit: Duration,
) -> Result<(), AuthorityTransportError> {
    for (phase, deadline) in [
        (AuthorityDeadlinePhase::Connect, deadlines.connect),
        (AuthorityDeadlinePhase::Write, deadlines.write),
        (AuthorityDeadlinePhase::Read, deadlines.read),
    ] {
        if deadline.is_zero() {
            return Err(AuthorityTransportError::InvalidDeadline { phase });
        }
        if deadline > hard_limit {
            return Err(AuthorityTransportError::DeadlineTooLong {
                phase,
                configured: deadline,
                hard_limit,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_bounds(
    bounds: AuthorityTransportBounds,
    hard_limits: AuthorityTransportHardLimits,
) -> Result<(), AuthorityTransportError> {
    for (bound, configured, hard_limit) in [
        (
            "request",
            bounds.max_request_bytes,
            hard_limits.max_request_bytes,
        ),
        (
            "response",
            bounds.max_response_bytes,
            hard_limits.max_response_bytes,
        ),
    ] {
        let framed_hard_limit = hard_limit.min(u32::MAX as usize);
        if configured == 0 || configured > framed_hard_limit {
            return Err(AuthorityTransportError::InvalidBound {
                bound,
                configured,
                hard_limit: framed_hard_limit,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn read_single_response_frame(
    stream: &mut UnixStream,
    max_response_bytes: usize,
) -> Result<Vec<u8>, AuthorityTransportError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let received = read_exact_count(stream, &mut header)
        .await
        .map_err(|source| AuthorityTransportError::ReadFailed {
            phase: AuthorityReadPhase::Header,
            source,
        })?;
    if received != FRAME_HEADER_BYTES {
        return Err(AuthorityTransportError::TruncatedHeader {
            expected: FRAME_HEADER_BYTES,
            received,
        });
    }
    let declared = u32::from_be_bytes(header) as usize;
    if declared == 0 {
        return Err(AuthorityTransportError::EmptyResponse);
    }
    if declared > max_response_bytes {
        return Err(AuthorityTransportError::ResponseTooLarge {
            declared,
            limit: max_response_bytes,
        });
    }
    let mut response = vec![0_u8; declared];
    let received = read_exact_count(stream, &mut response)
        .await
        .map_err(|source| AuthorityTransportError::ReadFailed {
            phase: AuthorityReadPhase::Body,
            source,
        })?;
    if received != declared {
        return Err(AuthorityTransportError::TruncatedResponse { declared, received });
    }
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing).await {
        Ok(0) => Ok(response),
        Ok(_) => Err(AuthorityTransportError::TrailingResponseBytes),
        Err(source) => Err(AuthorityTransportError::ReadFailed {
            phase: AuthorityReadPhase::EndOfFrame,
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::{Builder, TempDir};
    use tokio::net::UnixListener;
    use tokio::task::JoinHandle;

    const TEST_DEADLINE: Duration = Duration::from_secs(2);
    const SHORT_DEADLINE: Duration = Duration::from_millis(30);

    fn socket_fixture() -> (TempDir, PathBuf, UnixListener) {
        let directory = Builder::new()
            .prefix("ryuki-authz-")
            .tempdir_in("/tmp")
            .expect("create short socket test directory");
        let path = directory.path().join("authority.sock");
        let listener = UnixListener::bind(&path).expect("bind fake authority");
        (directory, path, listener)
    }

    fn transport(path: PathBuf, read: Duration, response_limit: usize) -> UnixAuthorityTransport {
        UnixAuthorityTransport::new(
            path,
            AuthorityTransportDeadlines {
                connect: TEST_DEADLINE,
                write: TEST_DEADLINE,
                read,
            },
            AuthorityTransportBounds {
                max_request_bytes: 1024,
                max_response_bytes: response_limit,
            },
            AuthorityTransportHardLimits {
                max_socket_path_bytes: 103,
                max_phase_deadline: Duration::from_secs(30),
                max_request_bytes: 1024,
                max_response_bytes: 1024,
            },
        )
        .expect("construct authority transport")
    }

    async fn read_request(stream: &mut UnixStream) {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        stream
            .read_exact(&mut header)
            .await
            .expect("request header");
        let mut body = vec![0_u8; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut body).await.expect("request body");
    }

    fn spawn<F, Fut>(listener: UnixListener, handler: F) -> JoinHandle<()>
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            handler(stream).await;
        })
    }

    #[test]
    fn constructor_enforces_deadline_bound_and_u32_frame_limit() {
        let path = PathBuf::from("/tmp/ryuki-authority.sock");
        let invalid_deadline = UnixAuthorityTransport::new(
            path.clone(),
            AuthorityTransportDeadlines {
                connect: Duration::ZERO,
                write: TEST_DEADLINE,
                read: TEST_DEADLINE,
            },
            AuthorityTransportBounds {
                max_request_bytes: 1,
                max_response_bytes: 1,
            },
            AuthorityTransportHardLimits {
                max_socket_path_bytes: 103,
                max_phase_deadline: Duration::from_secs(30),
                max_request_bytes: 1,
                max_response_bytes: 1,
            },
        );
        assert!(matches!(
            invalid_deadline,
            Err(AuthorityTransportError::InvalidDeadline {
                phase: AuthorityDeadlinePhase::Connect
            })
        ));

        #[cfg(target_pointer_width = "64")]
        {
            let over_frame_limit = u32::MAX as usize + 1;
            let invalid_frame_bound = UnixAuthorityTransport::new(
                path,
                AuthorityTransportDeadlines {
                    connect: TEST_DEADLINE,
                    write: TEST_DEADLINE,
                    read: TEST_DEADLINE,
                },
                AuthorityTransportBounds {
                    max_request_bytes: over_frame_limit,
                    max_response_bytes: 1,
                },
                AuthorityTransportHardLimits {
                    max_socket_path_bytes: 103,
                    max_phase_deadline: Duration::from_secs(30),
                    max_request_bytes: over_frame_limit,
                    max_response_bytes: 1,
                },
            );
            assert!(matches!(
                invalid_frame_bound,
                Err(AuthorityTransportError::InvalidBound {
                    bound: "request",
                    configured,
                    hard_limit,
                }) if configured == over_frame_limit && hard_limit == u32::MAX as usize
            ));
        }
    }

    #[tokio::test]
    async fn successful_exchange_preserves_exact_request_and_response_bytes() {
        let (_directory, path, listener) = socket_fixture();
        let server = spawn(listener, |mut stream| async move {
            let mut header = [0_u8; FRAME_HEADER_BYTES];
            stream.read_exact(&mut header).await.unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, b"exact request");
            stream.write_all(&5_u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"exact").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let response = transport(path, TEST_DEADLINE, 1024)
            .exchange(b"exact request")
            .await
            .unwrap();
        assert_eq!(response, b"exact");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn request_bounds_fail_before_connecting() {
        let transport = transport(
            PathBuf::from("/tmp/ryuki-no-authority.sock"),
            TEST_DEADLINE,
            1024,
        );
        assert!(matches!(
            transport.exchange(b"").await,
            Err(AuthorityTransportError::EmptyRequest)
        ));
        assert!(matches!(
            transport.exchange(&vec![0_u8; 1025]).await,
            Err(AuthorityTransportError::RequestTooLarge {
                actual: 1025,
                limit: 1024
            })
        ));
    }

    #[tokio::test]
    async fn stalled_response_hits_the_read_deadline() {
        let (_directory, path, listener) = socket_fixture();
        let server = spawn(listener, |mut stream| async move {
            read_request(&mut stream).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        });
        assert!(matches!(
            transport(path, SHORT_DEADLINE, 1024)
                .exchange(b"request")
                .await,
            Err(AuthorityTransportError::ReadTimedOut { .. })
        ));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn timeout_covers_a_held_open_response() {
        let (_directory, path, listener) = socket_fixture();
        let server = spawn(listener, |mut stream| async move {
            read_request(&mut stream).await;
            stream.write_all(&2_u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"ok").await.unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        });
        assert!(matches!(
            transport(path, SHORT_DEADLINE, 1024)
                .exchange(b"request")
                .await,
            Err(AuthorityTransportError::ReadTimedOut { .. })
        ));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn truncated_header_and_body_are_distinguished() {
        let (_directory, path, listener) = socket_fixture();
        let server = spawn(listener, |mut stream| async move {
            read_request(&mut stream).await;
            stream.write_all(&[0, 0]).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        assert!(matches!(
            transport(path, TEST_DEADLINE, 1024)
                .exchange(b"request")
                .await,
            Err(AuthorityTransportError::TruncatedHeader {
                expected: 4,
                received: 2
            })
        ));
        server.await.unwrap();

        let (_directory, path, listener) = socket_fixture();
        let server = spawn(listener, |mut stream| async move {
            read_request(&mut stream).await;
            stream.write_all(&8_u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"abc").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        assert!(matches!(
            transport(path, TEST_DEADLINE, 1024)
                .exchange(b"request")
                .await,
            Err(AuthorityTransportError::TruncatedResponse {
                declared: 8,
                received: 3
            })
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversize_and_trailing_bytes_fail_closed() {
        let (_directory, path, listener) = socket_fixture();
        let server = spawn(listener, |mut stream| async move {
            read_request(&mut stream).await;
            stream.write_all(&65_u32.to_be_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        assert!(matches!(
            transport(path, TEST_DEADLINE, 64)
                .exchange(b"request")
                .await,
            Err(AuthorityTransportError::ResponseTooLarge {
                declared: 65,
                limit: 64
            })
        ));
        server.await.unwrap();

        let (_directory, path, listener) = socket_fixture();
        let server = spawn(listener, |mut stream| async move {
            read_request(&mut stream).await;
            stream.write_all(&2_u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"ok!").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        assert!(matches!(
            transport(path, TEST_DEADLINE, 64)
                .exchange(b"request")
                .await,
            Err(AuthorityTransportError::TrailingResponseBytes)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn protocol_failure_is_not_retried() {
        let (_directory, path, listener) = socket_fixture();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            stream.write_all(&[0]).await.unwrap();
            stream.shutdown().await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(80), listener.accept())
                    .await
                    .is_err()
            );
        });
        assert!(matches!(
            transport(path, TEST_DEADLINE, 1024)
                .exchange(b"request")
                .await,
            Err(AuthorityTransportError::TruncatedHeader { .. })
        ));
        server.await.unwrap();
    }
}
