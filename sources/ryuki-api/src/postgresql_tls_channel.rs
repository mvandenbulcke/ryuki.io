//! Exact production PostgreSQL TLS channel establishment.
//!
//! SQLx 0.8 does not expose the Rustls connection it owns. Production
//! migrations therefore establish and measure one TLS stream here, then hand
//! that exact stream to one SQLx `PgConnection` through an owner-only,
//! single-use Unix-domain relay. There is no reconnect or fallback path.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ryuki_core::postgresql_infrastructure::{
    PostgresqlTlsChannelBinding, POSTGRESQL_TLS_EXPORTER_LABEL,
};
use ryuki_core::security_profile::{
    postgresql_provider_route_binding_digest, PostgresqlProviderRouteBinding,
    ProductionDatabaseProvider, POSTGRESQL_PROVIDER_ROUTE_MODE_DIRECT_SESSION_V1,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::{Connection, PgConnection};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::rustls::client::Resumption;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use tokio_rustls::{client::TlsStream, TlsConnector};
use zeroize::Zeroize;

const POSTGRESQL_SSL_REQUEST_CODE: u32 = 80_877_103;
const POSTGRESQL_PROTOCOL_VERSION_3: u32 = 196_608;
const POSTGRESQL_RELAY_WORKSPACE: &str = "/run/ryuki-postgresql-relay";
const MAX_CA_BUNDLE_BYTES: u64 = 256 * 1024;
const MAX_CA_CERTIFICATES: usize = 32;
const MAX_POSTGRESQL_STARTUP_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_POSTGRESQL_AUTH_MESSAGE_BYTES: usize = 64 * 1024;
const TLS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub(crate) enum PostgresqlTlsChannelError {
    #[error("PostgreSQL TLS target is invalid: {0}")]
    Target(String),
    #[error("PostgreSQL TLS channel failed: {0}")]
    Channel(String),
    #[error("PostgreSQL TLS relay failed: {0}")]
    Relay(String),
    #[error("SQLx could not establish the relayed PostgreSQL session")]
    Sqlx(#[source] sqlx::Error),
}

pub(crate) struct ProductionPostgresqlTarget {
    hostname: String,
    port: u16,
    username: String,
    password: String,
    database: String,
    root_certificate_path: PathBuf,
}

impl fmt::Debug for ProductionPostgresqlTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionPostgresqlTarget")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("root_certificate_path", &self.root_certificate_path)
            .finish_non_exhaustive()
    }
}

impl Drop for ProductionPostgresqlTarget {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl ProductionPostgresqlTarget {
    pub(crate) fn new(
        hostname: String,
        port: u16,
        username: String,
        password: String,
        database: String,
        root_certificate_path: PathBuf,
    ) -> Result<Self, PostgresqlTlsChannelError> {
        if hostname.is_empty()
            || port == 0
            || username.is_empty()
            || password.is_empty()
            || database.is_empty()
            || !root_certificate_path.is_absolute()
        {
            return Err(PostgresqlTlsChannelError::Target(
                "target fields are empty or noncanonical".into(),
            ));
        }
        Ok(Self {
            hostname,
            port,
            username,
            password,
            database,
            root_certificate_path,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_projection(&self) -> (&str, u16, &str, &str, &Path) {
        (
            &self.hostname,
            self.port,
            &self.username,
            &self.database,
            &self.root_certificate_path,
        )
    }

    pub(crate) async fn establish(
        self,
        provider: ProductionDatabaseProvider,
        expected_route_digest: &str,
        exporter_context: &[u8],
    ) -> Result<EstablishedPostgresqlTlsChannel, PostgresqlTlsChannelError> {
        let ca = read_bounded_ca_bundle(&self.root_certificate_path).await?;
        let trust_anchor_bundle_digest = sha256_digest(&ca);
        let roots = exclusive_root_store(&ca)?;
        let crypto_provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .map_err(|error| PostgresqlTlsChannelError::Channel(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.resumption = Resumption::disabled();

        let mut tcp = timeout(
            TLS_CONNECT_TIMEOUT,
            TcpStream::connect((self.hostname.as_str(), self.port)),
        )
        .await
        .map_err(|_| PostgresqlTlsChannelError::Channel("TCP connect timed out".into()))?
        .map_err(|error| PostgresqlTlsChannelError::Channel(error.to_string()))?;
        tcp.set_nodelay(true)
            .map_err(|error| PostgresqlTlsChannelError::Channel(error.to_string()))?;
        let peer = tcp
            .peer_addr()
            .map_err(|error| PostgresqlTlsChannelError::Channel(error.to_string()))?;
        let mut ssl_request = Vec::with_capacity(8);
        ssl_request.extend_from_slice(&8_u32.to_be_bytes());
        ssl_request.extend_from_slice(&POSTGRESQL_SSL_REQUEST_CODE.to_be_bytes());
        let response = timeout(TLS_CONNECT_TIMEOUT, async {
            tcp.write_all(&ssl_request).await?;
            let mut response = [0_u8; 1];
            tcp.read_exact(&mut response).await?;
            Ok::<[u8; 1], std::io::Error>(response)
        })
        .await
        .map_err(|_| PostgresqlTlsChannelError::Channel("PostgreSQL TLS upgrade timed out".into()))?
        .map_err(|error| PostgresqlTlsChannelError::Channel(error.to_string()))?;
        if response != *b"S" {
            return Err(PostgresqlTlsChannelError::Channel(
                "server refused the exact PostgreSQL TLS upgrade".into(),
            ));
        }
        let server_name = ServerName::try_from(self.hostname.clone())
            .map_err(|error| PostgresqlTlsChannelError::Target(error.to_string()))?;
        let tls = timeout(
            TLS_CONNECT_TIMEOUT,
            TlsConnector::from(Arc::new(config)).connect(server_name, tcp),
        )
        .await
        .map_err(|_| PostgresqlTlsChannelError::Channel("TLS handshake timed out".into()))?
        .map_err(|error| PostgresqlTlsChannelError::Channel(error.to_string()))?;
        let route = PostgresqlProviderRouteBinding {
            route_mode: POSTGRESQL_PROVIDER_ROUTE_MODE_DIRECT_SESSION_V1.to_owned(),
            database_provider: provider,
            endpoint_dns_name: self.hostname.clone(),
            endpoint_port: self.port,
            trust_anchor_bundle_digest,
            peer_leaf_certificate_digest: observed_peer_leaf_certificate_digest(&tls)?,
        };
        let route_digest = postgresql_provider_route_binding_digest(&route)
            .map_err(|error| PostgresqlTlsChannelError::Target(error.to_string()))?;
        if route_digest != expected_route_digest {
            return Err(PostgresqlTlsChannelError::Target(
                "TLS peer leaf or provider route differs from the receipt-bound direct session"
                    .into(),
            ));
        }
        let binding = observe_channel(
            &tls,
            &self.hostname,
            peer.ip(),
            peer.port(),
            &route,
            exporter_context,
        )?;
        Ok(EstablishedPostgresqlTlsChannel {
            target: self,
            tls,
            binding,
        })
    }
}

pub(crate) struct EstablishedPostgresqlTlsChannel {
    target: ProductionPostgresqlTarget,
    tls: TlsStream<TcpStream>,
    binding: PostgresqlTlsChannelBinding,
}

impl EstablishedPostgresqlTlsChannel {
    pub(crate) fn binding(&self) -> &PostgresqlTlsChannelBinding {
        &self.binding
    }

    pub(crate) async fn connect_sqlx(
        self,
        application_name: &str,
    ) -> Result<ChannelBoundProductionPgConnection, PostgresqlTlsChannelError> {
        let socket_directory = tempfile::Builder::new()
            .prefix("ryuki-pg-")
            .tempdir_in(POSTGRESQL_RELAY_WORKSPACE)
            .map_err(|error| PostgresqlTlsChannelError::Relay(error.to_string()))?;
        std::fs::set_permissions(
            socket_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(|error| PostgresqlTlsChannelError::Relay(error.to_string()))?;
        let socket_path = socket_directory
            .path()
            .join(format!(".s.PGSQL.{}", self.target.port));
        let listener = UnixListener::bind(&socket_path)
            .map_err(|error| PostgresqlTlsChannelError::Relay(error.to_string()))?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| PostgresqlTlsChannelError::Relay(error.to_string()))?;
        let expected_pid = i32::try_from(std::process::id())
            .map_err(|_| PostgresqlTlsChannelError::Relay("process id is out of range".into()))?;
        let mut tls = self.tls;
        let relay: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let (mut local, _) = timeout(RELAY_ACCEPT_TIMEOUT, listener.accept())
                .await
                .map_err(|_| "relay accept timed out".to_owned())?
                .map_err(|error| error.to_string())?;
            drop(listener);
            let _ = std::fs::remove_file(&socket_path);
            let credentials = local.peer_cred().map_err(|error| error.to_string())?;
            if credentials.pid() != Some(expected_pid) {
                return Err("relay peer process does not own the SQLx connection".into());
            }
            timeout(
                RELAY_AUTH_TIMEOUT,
                relay_postgresql_scram_authentication(&mut local, &mut tls),
            )
            .await
            .map_err(|_| "PostgreSQL SCRAM authentication relay timed out".to_owned())??;
            tokio::io::copy_bidirectional(&mut local, &mut tls)
                .await
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        let options = PgConnectOptions::new_without_pgpass()
            .socket(socket_directory.path())
            .port(self.target.port)
            .username(&self.target.username)
            .password(&self.target.password)
            .database(&self.target.database)
            .ssl_mode(PgSslMode::Disable)
            .application_name(application_name);
        let connection =
            match timeout(TLS_CONNECT_TIMEOUT, PgConnection::connect_with(&options)).await {
                Ok(Ok(connection)) => connection,
                Ok(Err(error)) => {
                    relay.abort();
                    return Err(PostgresqlTlsChannelError::Sqlx(error));
                }
                Err(_) => {
                    relay.abort();
                    return Err(PostgresqlTlsChannelError::Relay(
                        "SQLx relay connect timed out".into(),
                    ));
                }
            };
        Ok(ChannelBoundProductionPgConnection {
            connection,
            binding: self.binding,
            relay,
            _socket_directory: socket_directory,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScramAuthenticationState {
    Sasl,
    Continue,
    Final,
    AuthenticationOk,
    StartupCompletion,
}

#[derive(Clone, Copy, Debug)]
struct ScramMechanisms {
    sha256: bool,
    sha256_plus: bool,
}

struct PostgresqlTypedMessage {
    message_type: u8,
    body: Vec<u8>,
}

/// Relays only the PostgreSQL startup and a complete SCRAM authentication
/// exchange. The SQLx connection does not receive a password challenge until
/// the TLS peer has selected an allowed SCRAM mechanism. Normal protocol
/// traffic is relayed by the caller only after the authenticated startup has
/// reached `ReadyForQuery`. SQLx continues accepting password challenges after
/// `AuthenticationOk`, so this gate must reject any later authentication frame.
async fn relay_postgresql_scram_authentication<Local, Server>(
    local: &mut Local,
    server: &mut Server,
) -> Result<(), String>
where
    Local: AsyncRead + AsyncWrite + Unpin,
    Server: AsyncRead + AsyncWrite + Unpin,
{
    let startup = read_postgresql_startup_message(local).await?;
    server
        .write_all(&startup)
        .await
        .map_err(|error| format!("could not relay PostgreSQL startup message: {error}"))?;
    server
        .flush()
        .await
        .map_err(|error| format!("could not flush PostgreSQL startup message: {error}"))?;

    let mut state = ScramAuthenticationState::Sasl;
    let mut backend_key_data_seen = false;
    loop {
        let backend = read_postgresql_typed_message(
            server,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "backend authentication",
        )
        .await?;
        if backend.message_type == b'E' {
            return Err("PostgreSQL server rejected SCRAM authentication".into());
        }

        if state == ScramAuthenticationState::StartupCompletion {
            match backend.message_type {
                b'R' => {
                    let (authentication_code, _) =
                        parse_postgresql_authentication_request(&backend.body)?;
                    return Err(format!(
                        "PostgreSQL server requested authentication method {authentication_code} after AuthenticationOk"
                    ));
                }
                b'S' => validate_postgresql_parameter_status(&backend.body)?,
                b'K' if backend.body.len() == 8 && !backend_key_data_seen => {
                    backend_key_data_seen = true;
                }
                b'K' => {
                    return Err("PostgreSQL BackendKeyData is malformed or repeated".into());
                }
                b'Z' if backend.body == *b"I" && backend_key_data_seen => {
                    write_postgresql_typed_message(local, &backend, "ReadyForQuery").await?;
                    return Ok(());
                }
                b'Z' => {
                    return Err(
                        "PostgreSQL startup ReadyForQuery is malformed or missing BackendKeyData"
                            .into(),
                    );
                }
                _ => {
                    return Err(format!(
                        "unexpected PostgreSQL backend message type 0x{:02x} before startup completed",
                        backend.message_type
                    ));
                }
            }
            write_postgresql_typed_message(local, &backend, "startup completion").await?;
            continue;
        }

        if backend.message_type != b'R' {
            return Err(format!(
                "unexpected PostgreSQL backend message type 0x{:02x} before authentication completed",
                backend.message_type
            ));
        }
        let (authentication_code, authentication_data) =
            parse_postgresql_authentication_request(&backend.body)?;

        match state {
            ScramAuthenticationState::Sasl if authentication_code == 10 => {
                let mechanisms = validate_scram_mechanisms(authentication_data)?;
                write_postgresql_typed_message(local, &backend, "AuthenticationSASL").await?;
                let frontend = read_postgresql_typed_message(
                    local,
                    MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
                    "SASL initial response",
                )
                .await?;
                if frontend.message_type != b'p' {
                    return Err("expected a PostgreSQL SASLInitialResponse PasswordMessage".into());
                }
                validate_scram_initial_response(&frontend.body, mechanisms)?;
                write_postgresql_typed_message(server, &frontend, "SASL initial response").await?;
                state = ScramAuthenticationState::Continue;
            }
            ScramAuthenticationState::Continue if authentication_code == 11 => {
                if authentication_data.is_empty() {
                    return Err("PostgreSQL AuthenticationSASLContinue payload is empty".into());
                }
                write_postgresql_typed_message(local, &backend, "AuthenticationSASLContinue")
                    .await?;
                let frontend = read_postgresql_typed_message(
                    local,
                    MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
                    "SASL response",
                )
                .await?;
                if frontend.message_type != b'p' || frontend.body.is_empty() {
                    return Err(
                        "expected a non-empty PostgreSQL SASLResponse PasswordMessage".into(),
                    );
                }
                write_postgresql_typed_message(server, &frontend, "SASL response").await?;
                state = ScramAuthenticationState::Final;
            }
            ScramAuthenticationState::Final if authentication_code == 12 => {
                if authentication_data.is_empty() {
                    return Err("PostgreSQL AuthenticationSASLFinal payload is empty".into());
                }
                write_postgresql_typed_message(local, &backend, "AuthenticationSASLFinal").await?;
                state = ScramAuthenticationState::AuthenticationOk;
            }
            ScramAuthenticationState::AuthenticationOk
                if authentication_code == 0 && authentication_data.is_empty() =>
            {
                write_postgresql_typed_message(local, &backend, "AuthenticationOk").await?;
                state = ScramAuthenticationState::StartupCompletion;
            }
            _ => {
                return Err(format!(
                    "unsupported or out-of-sequence PostgreSQL authentication request code {authentication_code}"
                ));
            }
        }
    }
}

async fn read_postgresql_startup_message<Reader>(reader: &mut Reader) -> Result<Vec<u8>, String>
where
    Reader: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .await
        .map_err(|error| format!("could not read PostgreSQL startup length: {error}"))?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| "PostgreSQL startup length is out of range".to_owned())?;
    if !(8..=MAX_POSTGRESQL_STARTUP_MESSAGE_BYTES).contains(&length) {
        return Err("PostgreSQL startup message is outside the bounded profile".into());
    }
    let mut body = vec![0_u8; length - 4];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| format!("could not read PostgreSQL startup body: {error}"))?;
    if body[..4] != POSTGRESQL_PROTOCOL_VERSION_3.to_be_bytes() {
        return Err("relay accepts only PostgreSQL protocol version 3 startup messages".into());
    }
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(&length_bytes);
    message.extend_from_slice(&body);
    Ok(message)
}

async fn read_postgresql_typed_message<Reader>(
    reader: &mut Reader,
    maximum_length: usize,
    context: &str,
) -> Result<PostgresqlTypedMessage, String>
where
    Reader: AsyncRead + Unpin,
{
    let mut message_type = [0_u8; 1];
    reader
        .read_exact(&mut message_type)
        .await
        .map_err(|error| format!("could not read PostgreSQL {context} message type: {error}"))?;
    let mut length_bytes = [0_u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .await
        .map_err(|error| format!("could not read PostgreSQL {context} message length: {error}"))?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| format!("PostgreSQL {context} message length is out of range"))?;
    if length < 4 || length > maximum_length {
        return Err(format!(
            "PostgreSQL {context} message is outside the bounded profile"
        ));
    }
    let mut body = vec![0_u8; length - 4];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| format!("could not read PostgreSQL {context} message body: {error}"))?;
    Ok(PostgresqlTypedMessage {
        message_type: message_type[0],
        body,
    })
}

async fn write_postgresql_typed_message<Writer>(
    writer: &mut Writer,
    message: &PostgresqlTypedMessage,
    context: &str,
) -> Result<(), String>
where
    Writer: AsyncWrite + Unpin,
{
    let length = u32::try_from(message.body.len() + 4)
        .map_err(|_| format!("PostgreSQL {context} message length is out of range"))?;
    writer
        .write_all(&[message.message_type])
        .await
        .map_err(|error| format!("could not relay PostgreSQL {context} message type: {error}"))?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| format!("could not relay PostgreSQL {context} message length: {error}"))?;
    writer
        .write_all(&message.body)
        .await
        .map_err(|error| format!("could not relay PostgreSQL {context} message body: {error}"))?;
    writer
        .flush()
        .await
        .map_err(|error| format!("could not flush PostgreSQL {context} message: {error}"))
}

fn parse_postgresql_authentication_request(body: &[u8]) -> Result<(u32, &[u8]), String> {
    let code = body
        .get(..4)
        .ok_or_else(|| "PostgreSQL AuthenticationRequest is truncated".to_owned())?;
    Ok((
        u32::from_be_bytes(
            code.try_into()
                .map_err(|_| "PostgreSQL authentication code is malformed".to_owned())?,
        ),
        &body[4..],
    ))
}

fn validate_scram_mechanisms(bytes: &[u8]) -> Result<ScramMechanisms, String> {
    let mut remaining = bytes;
    let mut mechanisms = ScramMechanisms {
        sha256: false,
        sha256_plus: false,
    };
    loop {
        let terminator = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| "PostgreSQL SASL mechanism list is not terminated".to_owned())?;
        let mechanism = &remaining[..terminator];
        remaining = &remaining[terminator + 1..];
        if mechanism.is_empty() {
            if !remaining.is_empty() {
                return Err("PostgreSQL SASL mechanism list has trailing data".into());
            }
            break;
        }
        match mechanism {
            b"SCRAM-SHA-256" if !mechanisms.sha256 => mechanisms.sha256 = true,
            b"SCRAM-SHA-256-PLUS" if !mechanisms.sha256_plus => mechanisms.sha256_plus = true,
            b"SCRAM-SHA-256" | b"SCRAM-SHA-256-PLUS" => {
                return Err("PostgreSQL SASL mechanism list repeats a mechanism".into());
            }
            _ => {
                return Err(
                    "PostgreSQL server offered a SASL mechanism outside the SCRAM profile".into(),
                );
            }
        }
    }
    if !mechanisms.sha256 {
        return Err("PostgreSQL server did not offer SCRAM-SHA-256".into());
    }
    Ok(mechanisms)
}

fn validate_scram_initial_response(body: &[u8], mechanisms: ScramMechanisms) -> Result<(), String> {
    let mechanism_terminator = body
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "PostgreSQL SASLInitialResponse mechanism is not terminated".to_owned())?;
    let mechanism = &body[..mechanism_terminator];
    let response = &body[mechanism_terminator + 1..];
    let selected_is_allowed = match mechanism {
        b"SCRAM-SHA-256" => mechanisms.sha256,
        b"SCRAM-SHA-256-PLUS" => mechanisms.sha256_plus,
        _ => false,
    };
    if !selected_is_allowed {
        return Err(
            "PostgreSQL client selected a SASL mechanism outside the offered SCRAM profile".into(),
        );
    }
    let length_bytes = response
        .get(..4)
        .ok_or_else(|| "PostgreSQL SASLInitialResponse length is truncated".to_owned())?;
    let response_length = i32::from_be_bytes(
        length_bytes
            .try_into()
            .map_err(|_| "PostgreSQL SASLInitialResponse length is malformed".to_owned())?,
    );
    if response_length <= 0 {
        return Err("PostgreSQL SCRAM initial response must be present".into());
    }
    let response_length = usize::try_from(response_length)
        .map_err(|_| "PostgreSQL SASLInitialResponse length is out of range".to_owned())?;
    if response[4..].len() != response_length {
        return Err("PostgreSQL SASLInitialResponse length does not match its payload".into());
    }
    Ok(())
}

fn validate_postgresql_parameter_status(body: &[u8]) -> Result<(), String> {
    let name_terminator = body
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "PostgreSQL ParameterStatus name is not terminated".to_owned())?;
    if name_terminator == 0 {
        return Err("PostgreSQL ParameterStatus name is empty".into());
    }
    let value = &body[name_terminator + 1..];
    let value_terminator = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "PostgreSQL ParameterStatus value is not terminated".to_owned())?;
    if value_terminator + 1 != value.len() {
        return Err("PostgreSQL ParameterStatus has trailing data".into());
    }
    Ok(())
}

pub(crate) struct ChannelBoundProductionPgConnection {
    connection: PgConnection,
    binding: PostgresqlTlsChannelBinding,
    relay: JoinHandle<Result<(), String>>,
    _socket_directory: TempDir,
}

impl ChannelBoundProductionPgConnection {
    pub(crate) fn connection_mut(&mut self) -> &mut PgConnection {
        &mut self.connection
    }

    pub(crate) fn binding(&self) -> &PostgresqlTlsChannelBinding {
        &self.binding
    }

    pub(crate) fn relay_is_active(&self) -> bool {
        !self.relay.is_finished()
    }

    pub(crate) async fn close(self) {
        let _ = self.connection.close().await;
        let mut relay = self.relay;
        if timeout(RELAY_SHUTDOWN_TIMEOUT, &mut relay).await.is_err() {
            relay.abort();
        }
    }

    pub(crate) async fn close_hard(self) {
        let _ = self.connection.close_hard().await;
        self.relay.abort();
    }
}

async fn read_bounded_ca_bundle(path: &Path) -> Result<Vec<u8>, PostgresqlTlsChannelError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| PostgresqlTlsChannelError::Target(error.to_string()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CA_BUNDLE_BYTES {
        return Err(PostgresqlTlsChannelError::Target(
            "exclusive CA bundle is not a bounded regular file".into(),
        ));
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|error| PostgresqlTlsChannelError::Target(error.to_string()))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CA_BUNDLE_BYTES {
        return Err(PostgresqlTlsChannelError::Target(
            "exclusive CA bundle changed size while being read".into(),
        ));
    }
    Ok(bytes)
}

fn exclusive_root_store(bytes: &[u8]) -> Result<RootCertStore, PostgresqlTlsChannelError> {
    let certificates = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PostgresqlTlsChannelError::Target(error.to_string()))?;
    if certificates.is_empty() || certificates.len() > MAX_CA_CERTIFICATES {
        return Err(PostgresqlTlsChannelError::Target(
            "exclusive CA bundle has an invalid certificate count".into(),
        ));
    }
    let unique = certificates
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect::<BTreeSet<_>>();
    if unique.len() != certificates.len() {
        return Err(PostgresqlTlsChannelError::Target(
            "exclusive CA bundle repeats a certificate".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| PostgresqlTlsChannelError::Target(error.to_string()))?;
    }
    Ok(roots)
}

fn observe_channel(
    tls: &TlsStream<TcpStream>,
    server_name: &str,
    peer_address: IpAddr,
    peer_port: u16,
    route: &PostgresqlProviderRouteBinding,
    exporter_context: &[u8],
) -> Result<PostgresqlTlsChannelBinding, PostgresqlTlsChannelError> {
    let (_, connection) = tls.get_ref();
    if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(PostgresqlTlsChannelError::Channel(
            "direct production session requires TLS 1.3".into(),
        ));
    }
    let suite = connection
        .negotiated_cipher_suite()
        .ok_or_else(|| PostgresqlTlsChannelError::Channel("TLS cipher is missing".into()))?
        .suite();
    let (cipher, bits) = match suite {
        tokio_rustls::rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => {
            ("tls_aes_128_gcm_sha256", 128)
        }
        tokio_rustls::rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => {
            ("tls_aes_256_gcm_sha384", 256)
        }
        tokio_rustls::rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
            ("tls_chacha20_poly1305_sha256", 256)
        }
        _ => {
            return Err(PostgresqlTlsChannelError::Channel(
                "TLS cipher is outside the direct-session profile".into(),
            ));
        }
    };
    let chain = connection
        .peer_certificates()
        .filter(|chain| !chain.is_empty())
        .ok_or_else(|| {
            PostgresqlTlsChannelError::Channel("TLS peer certificate is missing".into())
        })?;
    let mut chain_preimage = Vec::new();
    for certificate in chain {
        let length = u64::try_from(certificate.as_ref().len())
            .map_err(|_| PostgresqlTlsChannelError::Channel("certificate is oversized".into()))?;
        chain_preimage.extend_from_slice(&length.to_be_bytes());
        chain_preimage.extend_from_slice(certificate.as_ref());
    }
    let mut exporter = connection
        .export_keying_material(
            [0_u8; 32],
            POSTGRESQL_TLS_EXPORTER_LABEL,
            Some(exporter_context),
        )
        .map_err(|error| PostgresqlTlsChannelError::Channel(error.to_string()))?;
    let exporter_digest = sha256_digest(&exporter);
    exporter.zeroize();
    Ok(PostgresqlTlsChannelBinding {
        provider_route_binding_digest: postgresql_provider_route_binding_digest(route)
            .map_err(|error| PostgresqlTlsChannelError::Target(error.to_string()))?,
        server_name: server_name.to_owned(),
        peer_address: peer_address.to_string(),
        peer_port,
        trust_anchor_bundle_digest: route.trust_anchor_bundle_digest.clone(),
        peer_leaf_certificate_digest: sha256_digest(chain[0].as_ref()),
        peer_certificate_chain_digest: sha256_digest(&chain_preimage),
        exporter_digest,
        tls_protocol: "tlsv1.3".into(),
        tls_cipher_suite: cipher.into(),
        tls_cipher_bits: bits,
    })
}

fn observed_peer_leaf_certificate_digest(
    tls: &TlsStream<TcpStream>,
) -> Result<String, PostgresqlTlsChannelError> {
    let chain = tls
        .get_ref()
        .1
        .peer_certificates()
        .filter(|chain| !chain.is_empty())
        .ok_or_else(|| {
            PostgresqlTlsChannelError::Channel("TLS peer certificate chain is missing".into())
        })?;
    Ok(sha256_digest(chain[0].as_ref()))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn startup_message() -> Vec<u8> {
        let mut body = POSTGRESQL_PROTOCOL_VERSION_3.to_be_bytes().to_vec();
        body.extend_from_slice(b"user\0ryuki\0database\0ryuki\0\0");
        let mut message = u32::try_from(body.len() + 4)
            .expect("test startup length fits")
            .to_be_bytes()
            .to_vec();
        message.extend_from_slice(&body);
        message
    }

    fn authentication_message(code: u32, data: &[u8]) -> PostgresqlTypedMessage {
        let mut body = code.to_be_bytes().to_vec();
        body.extend_from_slice(data);
        PostgresqlTypedMessage {
            message_type: b'R',
            body,
        }
    }

    fn password_message(body: &[u8]) -> PostgresqlTypedMessage {
        PostgresqlTypedMessage {
            message_type: b'p',
            body: body.to_vec(),
        }
    }

    fn sasl_initial_response(mechanism: &[u8], response: &[u8]) -> Vec<u8> {
        let mut body = mechanism.to_vec();
        body.push(0);
        body.extend_from_slice(
            &i32::try_from(response.len())
                .expect("test response length fits")
                .to_be_bytes(),
        );
        body.extend_from_slice(response);
        body
    }

    async fn read_forwarded_startup<Reader>(reader: &mut Reader, expected: &[u8])
    where
        Reader: AsyncRead + Unpin,
    {
        let mut actual = vec![0_u8; expected.len()];
        reader
            .read_exact(&mut actual)
            .await
            .expect("read forwarded startup");
        assert_eq!(actual, expected);
    }

    async fn drive_valid_scram_to_authentication_ok(
        client: &mut tokio::io::DuplexStream,
        server: &mut tokio::io::DuplexStream,
    ) {
        let startup = startup_message();
        client.write_all(&startup).await.expect("write startup");
        read_forwarded_startup(server, &startup).await;

        write_postgresql_typed_message(
            server,
            &authentication_message(10, b"SCRAM-SHA-256\0\0"),
            "test AuthenticationSASL",
        )
        .await
        .expect("write AuthenticationSASL");
        read_postgresql_typed_message(
            client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationSASL",
        )
        .await
        .expect("read AuthenticationSASL");

        let initial = password_message(&sasl_initial_response(
            b"SCRAM-SHA-256",
            b"n,,n=ryuki,r=nonce",
        ));
        write_postgresql_typed_message(client, &initial, "test SASLInitialResponse")
            .await
            .expect("write SASLInitialResponse");
        read_postgresql_typed_message(
            server,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test SASLInitialResponse",
        )
        .await
        .expect("read SASLInitialResponse");

        write_postgresql_typed_message(
            server,
            &authentication_message(11, b"r=nonce-server,s=c2FsdA==,i=4096"),
            "test AuthenticationSASLContinue",
        )
        .await
        .expect("write AuthenticationSASLContinue");
        read_postgresql_typed_message(
            client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationSASLContinue",
        )
        .await
        .expect("read AuthenticationSASLContinue");

        write_postgresql_typed_message(
            client,
            &password_message(b"c=biws,r=nonce-server,p=proof"),
            "test SASLResponse",
        )
        .await
        .expect("write SASLResponse");
        read_postgresql_typed_message(
            server,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test SASLResponse",
        )
        .await
        .expect("read SASLResponse");

        write_postgresql_typed_message(
            server,
            &authentication_message(12, b"v=server-proof"),
            "test AuthenticationSASLFinal",
        )
        .await
        .expect("write AuthenticationSASLFinal");
        read_postgresql_typed_message(
            client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationSASLFinal",
        )
        .await
        .expect("read AuthenticationSASLFinal");

        write_postgresql_typed_message(
            server,
            &authentication_message(0, &[]),
            "test AuthenticationOk",
        )
        .await
        .expect("write AuthenticationOk");
        read_postgresql_typed_message(
            client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationOk",
        )
        .await
        .expect("read AuthenticationOk");
    }

    #[tokio::test]
    async fn relay_allows_a_complete_scram_sha_256_exchange() {
        let (mut client, mut relay_local) = duplex(128 * 1024);
        let (mut relay_backend, mut server) = duplex(128 * 1024);
        let relay = tokio::spawn(async move {
            relay_postgresql_scram_authentication(&mut relay_local, &mut relay_backend).await
        });

        let startup = startup_message();
        client.write_all(&startup).await.expect("write startup");
        read_forwarded_startup(&mut server, &startup).await;

        let sasl = authentication_message(10, b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
        write_postgresql_typed_message(&mut server, &sasl, "test AuthenticationSASL")
            .await
            .expect("write AuthenticationSASL");
        let forwarded = read_postgresql_typed_message(
            &mut client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationSASL",
        )
        .await
        .expect("read AuthenticationSASL");
        assert_eq!(forwarded.message_type, b'R');
        assert_eq!(forwarded.body, sasl.body);

        let client_first = sasl_initial_response(b"SCRAM-SHA-256", b"n,,n=ryuki,r=nonce");
        let initial = password_message(&client_first);
        write_postgresql_typed_message(&mut client, &initial, "test SASLInitialResponse")
            .await
            .expect("write SASLInitialResponse");
        let forwarded = read_postgresql_typed_message(
            &mut server,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test SASLInitialResponse",
        )
        .await
        .expect("read SASLInitialResponse");
        assert_eq!(forwarded.message_type, b'p');
        assert_eq!(forwarded.body, initial.body);

        let sasl_continue = authentication_message(11, b"r=nonce-server,s=c2FsdA==,i=4096");
        write_postgresql_typed_message(
            &mut server,
            &sasl_continue,
            "test AuthenticationSASLContinue",
        )
        .await
        .expect("write AuthenticationSASLContinue");
        let forwarded = read_postgresql_typed_message(
            &mut client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationSASLContinue",
        )
        .await
        .expect("read AuthenticationSASLContinue");
        assert_eq!(forwarded.body, sasl_continue.body);

        let client_final = password_message(b"c=biws,r=nonce-server,p=proof");
        write_postgresql_typed_message(&mut client, &client_final, "test SASLResponse")
            .await
            .expect("write SASLResponse");
        let forwarded = read_postgresql_typed_message(
            &mut server,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test SASLResponse",
        )
        .await
        .expect("read SASLResponse");
        assert_eq!(forwarded.message_type, b'p');
        assert_eq!(forwarded.body, client_final.body);

        let sasl_final = authentication_message(12, b"v=server-proof");
        write_postgresql_typed_message(&mut server, &sasl_final, "test AuthenticationSASLFinal")
            .await
            .expect("write AuthenticationSASLFinal");
        let forwarded = read_postgresql_typed_message(
            &mut client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationSASLFinal",
        )
        .await
        .expect("read AuthenticationSASLFinal");
        assert_eq!(forwarded.body, sasl_final.body);

        let authentication_ok = authentication_message(0, &[]);
        write_postgresql_typed_message(&mut server, &authentication_ok, "test AuthenticationOk")
            .await
            .expect("write AuthenticationOk");
        let forwarded = read_postgresql_typed_message(
            &mut client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test AuthenticationOk",
        )
        .await
        .expect("read AuthenticationOk");
        assert_eq!(forwarded.body, authentication_ok.body);

        let parameter_status = PostgresqlTypedMessage {
            message_type: b'S',
            body: [b"server_version\0".as_slice(), b"16.4\0".as_slice()].concat(),
        };
        write_postgresql_typed_message(&mut server, &parameter_status, "test ParameterStatus")
            .await
            .expect("write ParameterStatus");
        let forwarded = read_postgresql_typed_message(
            &mut client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test ParameterStatus",
        )
        .await
        .expect("read ParameterStatus");
        assert_eq!(forwarded.message_type, b'S');
        assert_eq!(forwarded.body, parameter_status.body);

        let backend_key_data = PostgresqlTypedMessage {
            message_type: b'K',
            body: [1_u32.to_be_bytes(), 2_u32.to_be_bytes()].concat(),
        };
        write_postgresql_typed_message(&mut server, &backend_key_data, "test BackendKeyData")
            .await
            .expect("write BackendKeyData");
        let forwarded = read_postgresql_typed_message(
            &mut client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test BackendKeyData",
        )
        .await
        .expect("read BackendKeyData");
        assert_eq!(forwarded.message_type, b'K');
        assert_eq!(forwarded.body, backend_key_data.body);

        let ready_for_query = PostgresqlTypedMessage {
            message_type: b'Z',
            body: vec![b'I'],
        };
        write_postgresql_typed_message(&mut server, &ready_for_query, "test ReadyForQuery")
            .await
            .expect("write ReadyForQuery");
        let forwarded = read_postgresql_typed_message(
            &mut client,
            MAX_POSTGRESQL_AUTH_MESSAGE_BYTES,
            "test ReadyForQuery",
        )
        .await
        .expect("read ReadyForQuery");
        assert_eq!(forwarded.message_type, b'Z');
        assert_eq!(forwarded.body, ready_for_query.body);

        relay
            .await
            .expect("relay task completes")
            .expect("SCRAM exchange is accepted");
    }

    async fn assert_authentication_code_is_rejected_without_forwarding(code: u32) {
        let (mut client, mut relay_local) = duplex(128 * 1024);
        let (mut relay_backend, mut server) = duplex(128 * 1024);
        let relay = tokio::spawn(async move {
            relay_postgresql_scram_authentication(&mut relay_local, &mut relay_backend).await
        });

        let startup = startup_message();
        client.write_all(&startup).await.expect("write startup");
        read_forwarded_startup(&mut server, &startup).await;
        write_postgresql_typed_message(
            &mut server,
            &authentication_message(code, &[]),
            "test rejected AuthenticationRequest",
        )
        .await
        .expect("write rejected AuthenticationRequest");

        let error = relay
            .await
            .expect("relay task completes")
            .expect_err("authentication method must be rejected");
        assert!(
            error.contains("unsupported or out-of-sequence"),
            "unexpected error: {error}"
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            client.read(&mut byte).await.expect("read closed relay"),
            0,
            "a rejected authentication request reached SQLx"
        );
    }

    #[tokio::test]
    async fn relay_rejects_password_disclosing_and_non_scram_authentication() {
        // Includes AuthenticationOk without SCRAM, Kerberos, cleartext password,
        // MD5 password, SCM credentials, GSS, GSS continuation, SSPI, OAuth, and
        // an unknown future authentication method.
        for code in [0, 2, 3, 5, 6, 7, 8, 9, 13, 99] {
            assert_authentication_code_is_rejected_without_forwarding(code).await;
        }
    }

    async fn assert_late_authentication_code_is_rejected_without_forwarding(code: u32) {
        let (mut client, mut relay_local) = duplex(128 * 1024);
        let (mut relay_backend, mut server) = duplex(128 * 1024);
        let relay = tokio::spawn(async move {
            relay_postgresql_scram_authentication(&mut relay_local, &mut relay_backend).await
        });

        drive_valid_scram_to_authentication_ok(&mut client, &mut server).await;
        write_postgresql_typed_message(
            &mut server,
            &authentication_message(code, &[]),
            "test late AuthenticationRequest",
        )
        .await
        .expect("write late AuthenticationRequest");

        let error = relay
            .await
            .expect("relay task completes")
            .expect_err("late password challenge must be rejected");
        assert!(error.contains("after AuthenticationOk"));
        let mut byte = [0_u8; 1];
        assert_eq!(
            client.read(&mut byte).await.expect("read closed relay"),
            0,
            "a late password request reached SQLx"
        );
    }

    #[tokio::test]
    async fn relay_rejects_password_challenges_after_authentication_ok() {
        for code in [3, 5] {
            assert_late_authentication_code_is_rejected_without_forwarding(code).await;
        }
    }

    #[test]
    fn scram_mechanism_profile_is_exact_and_requires_non_plus_scram() {
        let regular =
            validate_scram_mechanisms(b"SCRAM-SHA-256\0\0").expect("regular SCRAM is accepted");
        assert!(regular.sha256);
        assert!(!regular.sha256_plus);

        let both = validate_scram_mechanisms(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0")
            .expect("regular and channel-binding SCRAM are accepted");
        assert!(both.sha256);
        assert!(both.sha256_plus);

        assert!(validate_scram_mechanisms(b"SCRAM-SHA-256-PLUS\0\0").is_err());
        assert!(validate_scram_mechanisms(b"SCRAM-SHA-1\0SCRAM-SHA-256\0\0").is_err());
        assert!(validate_scram_mechanisms(b"SCRAM-SHA-256\0SCRAM-SHA-256\0\0").is_err());
        assert!(validate_scram_mechanisms(b"SCRAM-SHA-256\0\0trailing").is_err());
        assert!(validate_scram_mechanisms(b"SCRAM-SHA-256").is_err());
    }

    #[tokio::test]
    async fn relay_rejects_oversized_authentication_frame_without_allocating_it() {
        let (mut client, mut relay_local) = duplex(128 * 1024);
        let (mut relay_backend, mut server) = duplex(128 * 1024);
        let relay = tokio::spawn(async move {
            relay_postgresql_scram_authentication(&mut relay_local, &mut relay_backend).await
        });

        let startup = startup_message();
        client.write_all(&startup).await.expect("write startup");
        read_forwarded_startup(&mut server, &startup).await;
        server.write_all(b"R").await.expect("write frame type");
        server
            .write_all(&u32::MAX.to_be_bytes())
            .await
            .expect("write oversized frame length");

        let error = relay
            .await
            .expect("relay task completes")
            .expect_err("oversized frame must be rejected");
        assert!(error.contains("outside the bounded profile"));
    }
}
