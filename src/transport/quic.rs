use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use quinn::{Connection, Endpoint, EndpointConfig, RecvStream, SendStream, VarInt};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::transport::{TransportError, UdpAttempt, ensure_rustls_provider};

const ALPN_PROTOCOL: &[u8] = b"kmesh-ssh/1";
const STREAM_PREFACE: &[u8; 4] = b"KMS1";

#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub keep_alive_interval: Duration,
    pub max_idle_timeout: Duration,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: Duration::from_secs(15),
            max_idle_timeout: Duration::from_secs(60),
        }
    }
}

pub struct QuicAcceptor {
    endpoint: Endpoint,
}

impl QuicAcceptor {
    pub async fn accept(&self) -> Result<QuicByteStream, TransportError> {
        let incoming =
            self.endpoint.accept().await.ok_or_else(|| {
                TransportError::Quic("QUIC endpoint stopped accepting".to_owned())
            })?;
        let connection = incoming.await.map_err(map_connection_error)?;
        let (mut send, mut recv) = connection.accept_bi().await.map_err(map_connection_error)?;
        let mut preface = [0; STREAM_PREFACE.len()];
        recv.read_exact(&mut preface)
            .await
            .map_err(|error| TransportError::Quic(format!("read QUIC stream preface: {error}")))?;
        if &preface != STREAM_PREFACE {
            send.reset(VarInt::from_u32(1)).map_err(|error| {
                TransportError::Quic(format!("reset stream with invalid preface: {error}"))
            })?;
            recv.stop(VarInt::from_u32(1)).map_err(|error| {
                TransportError::Quic(format!("stop stream with invalid preface: {error}"))
            })?;
            return Err(TransportError::ProtocolViolation(
                "QUIC stream preface is not KMS1".to_owned(),
            ));
        }
        Ok(QuicByteStream::new(
            self.endpoint.clone(),
            connection,
            send,
            recv,
        ))
    }
}

pub struct QuicByteStream {
    _endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    send_finished: bool,
    receive_finished: bool,
}

impl QuicByteStream {
    fn new(endpoint: Endpoint, connection: Connection, send: SendStream, recv: RecvStream) -> Self {
        Self {
            _endpoint: endpoint,
            connection,
            send,
            recv,
            send_finished: false,
            receive_finished: false,
        }
    }

    /// Reset both directions of this QUIC stream.
    pub fn reset(&mut self, code: u32) -> Result<(), TransportError> {
        let code = VarInt::from_u32(code);
        self.send
            .reset(code)
            .map_err(|error| TransportError::Quic(format!("reset QUIC send stream: {error}")))?;
        self.recv
            .stop(code)
            .map_err(|error| TransportError::Quic(format!("stop QUIC receive stream: {error}")))?;
        self.send_finished = true;
        self.receive_finished = true;
        Ok(())
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl AsyncRead for QuicByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.receive_finished || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buffer.filled().len();
        match Pin::new(&mut self.recv).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() == before {
                    self.receive_finished = true;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(classify_read_io(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuicByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.send_finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC send direction is finished",
            )));
        }
        match AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buffer) {
            Poll::Ready(Ok(bytes)) => Poll::Ready(Ok(bytes)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(classify_write_io(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(classify_write_io(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.send_finished {
            return Poll::Ready(Ok(()));
        }
        match self.send.finish() {
            Ok(()) => {
                self.send_finished = true;
                Poll::Ready(Ok(()))
            }
            Err(_) => Poll::Ready(Err(write_error_to_io(quinn::WriteError::ClosedStream))),
        }
    }
}

impl UdpAttempt {
    pub fn into_quic_server(
        self,
        _target_id: uuid::Uuid,
        certificate_pem: &str,
        private_key_pem: &str,
        config: QuicConfig,
    ) -> Result<QuicAcceptor, TransportError> {
        ensure_rustls_provider();
        let certificates =
            rustls_pemfile::certs(&mut io::BufReader::new(certificate_pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    TransportError::Configuration(format!("parse target certificate PEM: {error}"))
                })?;
        let private_key =
            rustls_pemfile::private_key(&mut io::BufReader::new(private_key_pem.as_bytes()))
                .map_err(|error| {
                    TransportError::Configuration(format!("parse target private key PEM: {error}"))
                })?
                .ok_or_else(|| {
                    TransportError::Configuration("target private key PEM is empty".to_owned())
                })?;

        let mut crypto = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|error| {
                TransportError::Configuration(format!("build target TLS certificate: {error}"))
            })?;
        crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(|error| {
                TransportError::Configuration(format!("build QUIC TLS: {error}"))
            })?,
        ));
        server_config.transport_config(Arc::new(transport_config(config)?));

        let socket = self.into_std_socket().map_err(TransportError::Network)?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(TransportError::Network)?;
        Ok(QuicAcceptor { endpoint })
    }

    pub async fn into_quic_client(
        self,
        target_id: uuid::Uuid,
        peer: SocketAddr,
        certificate_der: Vec<u8>,
        expected_fingerprint: &str,
        config: QuicConfig,
    ) -> Result<QuicByteStream, TransportError> {
        ensure_rustls_provider();
        let actual_fingerprint = format!(
            "sha256:{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(&certificate_der))
        );
        if actual_fingerprint != expected_fingerprint {
            return Err(TransportError::Authentication(
                "target certificate fingerprint differs from the signed offer".to_owned(),
            ));
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificate_der))
            .map_err(|error| {
                TransportError::Authentication(format!("invalid target certificate: {error}"))
            })?;
        let mut crypto = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|error| {
                TransportError::Configuration(format!("build QUIC TLS: {error}"))
            })?,
        ));
        client_config.transport_config(Arc::new(transport_config(config)?));

        let socket = self.into_std_socket().map_err(TransportError::Network)?;
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(TransportError::Network)?;
        endpoint.set_default_client_config(client_config);
        let server_name = format!("target-{target_id}.kmesh.invalid");
        let connection = endpoint
            .connect(peer, &server_name)
            .map_err(|error| TransportError::Quic(format!("start QUIC connection: {error}")))?
            .await
            .map_err(map_connection_error)?;
        let (mut send, recv) = connection.open_bi().await.map_err(map_connection_error)?;
        send.write_all(STREAM_PREFACE)
            .await
            .map_err(|error| TransportError::Quic(format!("write QUIC stream preface: {error}")))?;
        send.flush()
            .await
            .map_err(|error| TransportError::Quic(format!("flush QUIC stream preface: {error}")))?;
        Ok(QuicByteStream::new(endpoint, connection, send, recv))
    }
}

fn transport_config(config: QuicConfig) -> Result<quinn::TransportConfig, TransportError> {
    let idle_timeout = quinn::IdleTimeout::try_from(config.max_idle_timeout).map_err(|error| {
        TransportError::Configuration(format!("invalid QUIC idle timeout: {error}"))
    })?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(Some(config.keep_alive_interval));
    Ok(transport)
}

fn map_connection_error(error: quinn::ConnectionError) -> TransportError {
    match error {
        quinn::ConnectionError::TimedOut => TransportError::Timeout("QUIC connection"),
        quinn::ConnectionError::TransportError(error) => {
            let code = u64::from(error.code);
            if (0x100..0x200).contains(&code) {
                TransportError::Authentication(format!("QUIC TLS alert {}", code - 0x100))
            } else {
                TransportError::ProtocolViolation(format!("QUIC transport error: {error}"))
            }
        }
        quinn::ConnectionError::VersionMismatch => {
            TransportError::ProtocolViolation("QUIC version negotiation failed".to_owned())
        }
        quinn::ConnectionError::CidsExhausted => {
            TransportError::Configuration("QUIC connection IDs exhausted".to_owned())
        }
        other => TransportError::Quic(format!("QUIC connection ended: {other}")),
    }
}

fn connection_error_to_io(error: quinn::ConnectionError) -> io::Error {
    let kind = match error {
        quinn::ConnectionError::TimedOut => io::ErrorKind::TimedOut,
        quinn::ConnectionError::Reset => io::ErrorKind::ConnectionReset,
        quinn::ConnectionError::TransportError(ref error)
            if (0x100..0x200).contains(&u64::from(error.code)) =>
        {
            io::ErrorKind::PermissionDenied
        }
        quinn::ConnectionError::TransportError(_) | quinn::ConnectionError::VersionMismatch => {
            io::ErrorKind::InvalidData
        }
        _ => io::ErrorKind::ConnectionAborted,
    };
    io::Error::new(kind, map_connection_error(error))
}

fn read_error_to_io(error: quinn::ReadError) -> io::Error {
    match error {
        quinn::ReadError::ConnectionLost(error) => connection_error_to_io(error),
        quinn::ReadError::Reset(code) => io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("QUIC stream reset: {code}"),
        ),
        quinn::ReadError::ZeroRttRejected => {
            io::Error::new(io::ErrorKind::ConnectionAborted, "QUIC 0-RTT was rejected")
        }
        quinn::ReadError::ClosedStream => {
            io::Error::new(io::ErrorKind::BrokenPipe, "QUIC receive stream is closed")
        }
        quinn::ReadError::IllegalOrderedRead => io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC stream read is not ordered",
        ),
    }
}

fn write_error_to_io(error: quinn::WriteError) -> io::Error {
    match error {
        quinn::WriteError::ConnectionLost(error) => connection_error_to_io(error),
        quinn::WriteError::Stopped(code) => io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("QUIC stream stopped: {code}"),
        ),
        quinn::WriteError::ZeroRttRejected => {
            io::Error::new(io::ErrorKind::ConnectionAborted, "QUIC 0-RTT was rejected")
        }
        quinn::WriteError::ClosedStream => {
            io::Error::new(io::ErrorKind::BrokenPipe, "QUIC send stream is closed")
        }
    }
}

fn classify_read_io(error: io::Error) -> io::Error {
    if let Some(read_error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<quinn::ReadError>())
    {
        read_error_to_io(read_error.clone())
    } else {
        error
    }
}

fn classify_write_io(error: io::Error) -> io::Error {
    if let Some(write_error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<quinn::WriteError>())
    {
        write_error_to_io(write_error.clone())
    } else {
        error
    }
}
