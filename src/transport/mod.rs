//! Direct UDP/QUIC and WSS relay transports.

mod http;
mod quic;
mod relay;
mod stun;
mod udp;

use std::io;

pub use http::{BoxedIo, WsStream, connect_wss, http_client};
pub use quic::{QuicAcceptor, QuicByteStream, QuicConfig};
pub use relay::RelayByteStream;
pub use stun::serve_stun;
pub use udp::{ProbeResult, UdpAttempt};

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
    #[error("TLS configuration or handshake failed: {0}")]
    Tls(String),
    #[error("QUIC failed: {0}")]
    Quic(String),
    #[error("STUN failed: {0}")]
    Stun(String),
    #[error("WebSocket failed: {0}")]
    WebSocket(String),
    #[error("invalid transport configuration: {0}")]
    Configuration(String),
}

impl TransportError {
    pub fn is_security_failure(&self) -> bool {
        matches!(self, Self::Authentication(_) | Self::ProtocolViolation(_))
    }
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
