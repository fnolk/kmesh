//! Iroh QUIC transport for SSH streams and HTTPS control-plane connections.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("kmesh transport supports Linux and macOS only");

mod http;
mod iroh;
mod qad;
mod udp_handoff;

use std::{error::Error as StdError, io};

pub use http::{BoxedIo, WsStream, connect_wss, http_client};
pub use iroh::{
    HandoffOptions, IROH_SSH_ALPN, IrohByteStream, IrohEndpointOptions, IrohPathKind,
    IrohPathStats, IrohSelectedPath, RelayChoice, accept_peer, allowed_relay_urls, connect_peer,
    create_endpoint, snapshot_iroh_paths, validate_endpoint_addr, wait_endpoint_ready,
};
pub use qad::{QadObservation, QadReflector, observe_ipv4_mappings};
pub use udp_handoff::{
    DiscoveredUdpSocket, LocalBindState, MappingDiscovery, PreparedPunch, PunchCounters,
    PunchError, PunchIdentity, PunchRole, PunchSelection, discover_ipv4_mappings,
};

/// A transport error with an explicit security and network classification.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport authentication failed: {0}")]
    Authentication(String),
    #[error("transport protocol violation: {0}")]
    ProtocolViolation(String),
    #[error("network I/O failed: {0}")]
    Network(#[source] io::Error),
    #[error("{0} timed out")]
    Timeout(&'static str),
    #[error("Iroh endpoint is closed")]
    EndpointClosed,
    #[error("TLS configuration or handshake failed: {0}")]
    Tls(String),
    #[error("Iroh transport failed: {0}")]
    Iroh(String),
    #[error("Iroh connection failed: {0}")]
    IrohConnect(#[source] ::iroh::endpoint::ConnectError),
    #[error("Iroh connection handshake failed: {0}")]
    IrohConnecting(#[source] ::iroh::endpoint::ConnectingError),
    #[error("Iroh connection closed during setup: {0}")]
    IrohConnection(#[source] ::iroh::endpoint::ConnectionError),
    #[error("WebSocket failed: {0}")]
    WebSocket(String),
    #[error("invalid transport configuration: {0}")]
    Configuration(String),
}

impl TransportError {
    pub fn is_security_failure(&self) -> bool {
        matches!(self, Self::Authentication(_) | Self::ProtocolViolation(_))
    }

    pub fn is_auth_failure(&self) -> bool {
        match self {
            Self::Authentication(_) => true,
            Self::IrohConnect(error) => is_auth_failure_source(error),
            Self::IrohConnecting(error) => is_auth_failure_source(error),
            Self::IrohConnection(error) => is_auth_failure_source(error),
            _ => false,
        }
    }

    pub fn is_network_failure(&self) -> bool {
        match self {
            Self::Timeout(_) => true,
            Self::Network(error) => is_network_io_error(error.kind()),
            Self::IrohConnect(error) => is_network_failure_source(error),
            Self::IrohConnecting(error) => is_network_failure_source(error),
            Self::IrohConnection(error) => is_network_failure_source(error),
            _ => false,
        }
    }
}

pub fn is_auth_failure_source(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<rustls::Error>()
            .is_some_and(|error| matches!(error, rustls::Error::InvalidCertificate(_)))
        {
            return true;
        }
        if error
            .downcast_ref::<::iroh::endpoint::AuthenticationError>()
            .is_some()
        {
            return true;
        }
        if let Some(error) = error.downcast_ref::<iroh_relay::client::ConnectError>() {
            match error {
                iroh_relay::client::ConnectError::Tls { .. }
                | iroh_relay::client::ConnectError::Handshake { .. }
                | iroh_relay::client::ConnectError::InvalidTlsServername { .. }
                | iroh_relay::client::ConnectError::InvalidRelayUrl { .. }
                | iroh_relay::client::ConnectError::InvalidWebsocketUrl { .. }
                | iroh_relay::client::ConnectError::MissingCryptoProvider { .. } => return true,
                iroh_relay::client::ConnectError::UnexpectedUpgradeStatus { code, .. }
                    if matches!(code.as_u16(), 401 | 403) =>
                {
                    return true;
                }
                _ => {}
            }
        }
        if let Some(error) = error.downcast_ref::<iroh_relay::client::DialError>() {
            match error {
                iroh_relay::client::DialError::ProxyConnectInvalidStatus { status, .. }
                    if status.as_u16() == 407 =>
                {
                    return true;
                }
                iroh_relay::client::DialError::ProxyInvalidUrl { .. }
                | iroh_relay::client::DialError::ProxyInvalidTlsServername { .. }
                | iroh_relay::client::DialError::ProxyInvalidTargetPort { .. } => return true,
                _ => {}
            }
        }
        current = error.source();
    }
    false
}

pub fn is_network_failure_source(error: &(dyn StdError + 'static)) -> bool {
    if is_auth_failure_source(error) {
        return false;
    }

    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<iroh_relay::client::DialError>() {
            match error {
                iroh_relay::client::DialError::Dns { .. }
                | iroh_relay::client::DialError::Timeout { .. } => return true,
                iroh_relay::client::DialError::Io { source, .. }
                    if is_network_io_error(source.kind()) =>
                {
                    return true;
                }
                _ => {}
            }
        }
        if error
            .downcast_ref::<::iroh::endpoint::ConnectionError>()
            .is_some_and(|error| matches!(error, ::iroh::endpoint::ConnectionError::TimedOut))
        {
            return true;
        }
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| is_network_io_error(error.kind()))
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn is_network_io_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        Self::Network(value)
    }
}

pub(crate) fn ensure_rustls_provider() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}
