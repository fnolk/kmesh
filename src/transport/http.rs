use std::io;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{WebSocketStream, client_async_with_config};

use crate::config::TlsConfig;
use crate::transport::{TransportError, ensure_rustls_provider};

const NETWORK_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const WSS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub type WsStream = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Build the REST client with configured trust roots and direct connections.
pub fn http_client(tls: &TlsConfig) -> Result<reqwest::Client, TransportError> {
    ensure_rustls_provider();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .tls_backend_rustls()
        .connect_timeout(NETWORK_CONNECT_TIMEOUT)
        .timeout(NETWORK_CONNECT_TIMEOUT);

    let certificates = load_reqwest_roots(&tls.ca_certificates)?;
    if !certificates.is_empty() {
        builder = builder.tls_certs_merge(certificates);
    }

    builder
        .build()
        .map_err(|error| TransportError::Tls(format!("build REST TLS client: {error}")))
}

/// Connect a WSS request directly.
pub async fn connect_wss<R>(request: R, tls: &TlsConfig) -> Result<WsStream, TransportError>
where
    R: IntoClientRequest + Unpin,
{
    tokio::time::timeout(WSS_HANDSHAKE_TIMEOUT, connect_wss_inner(request, tls))
        .await
        .map_err(|_| TransportError::Timeout("WSS connection and handshake"))?
}

async fn connect_wss_inner<R>(request: R, tls: &TlsConfig) -> Result<WsStream, TransportError>
where
    R: IntoClientRequest + Unpin,
{
    ensure_rustls_provider();
    let request = request.into_client_request().map_err(|error| {
        TransportError::Configuration(format!("invalid WebSocket request: {error}"))
    })?;
    let uri = request.uri();
    if uri.scheme_str() != Some("wss") {
        return Err(TransportError::Configuration(
            "secure WebSocket requests require the wss scheme".to_owned(),
        ));
    }
    let host = uri
        .host()
        .ok_or_else(|| TransportError::Configuration("WSS URL has no host".to_owned()))?;
    let socket_host = unbracket_host(host);
    let port = uri.port_u16().unwrap_or(443);
    let socket = TcpStream::connect((socket_host, port))
        .await
        .map_err(TransportError::Network)?;
    socket.set_nodelay(true).map_err(TransportError::Network)?;
    let roots = build_root_store(&tls.ca_certificates)?;
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_name = tls.server_name.as_deref().unwrap_or(socket_host);
    let server_name = ServerName::try_from(server_name.to_owned()).map_err(|error| {
        TransportError::Configuration(format!("invalid TLS server name: {error}"))
    })?;
    let stream = TlsConnector::from(config)
        .connect(server_name, socket)
        .await
        .map_err(|error| classify_tls_error(error, "WSS TLS handshake"))?;

    let (websocket, _response) =
        client_async_with_config(request, stream, Some(WebSocketConfig::default()))
            .await
            .map_err(map_websocket_handshake_error)?;
    Ok(websocket)
}

fn classify_tls_error(error: io::Error, context: &str) -> TransportError {
    let certificate_failure = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
        .is_some_and(|error| {
            matches!(
                error,
                rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
            )
        });
    if certificate_failure {
        TransportError::Authentication(format!("{context}: {error}"))
    } else {
        TransportError::Tls(format!("{context}: {error}"))
    }
}

fn map_websocket_handshake_error(error: tokio_tungstenite::tungstenite::Error) -> TransportError {
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response)
            if matches!(response.status().as_u16(), 401 | 403) =>
        {
            TransportError::Authentication(format!(
                "WSS server rejected credentials with HTTP {}",
                response.status()
            ))
        }
        tokio_tungstenite::tungstenite::Error::Http(response) => TransportError::ProtocolViolation(
            format!("WSS handshake returned HTTP {}", response.status()),
        ),
        error => TransportError::WebSocket(format!("WSS handshake: {error}")),
    }
}

fn load_reqwest_roots(
    paths: &[std::path::PathBuf],
) -> Result<Vec<reqwest::Certificate>, TransportError> {
    paths
        .iter()
        .map(|path| {
            let pem = std::fs::read(path).map_err(|error| {
                TransportError::Configuration(format!(
                    "read CA certificate {}: {error}",
                    path.display()
                ))
            })?;
            reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
                TransportError::Configuration(format!(
                    "parse CA certificate {}: {error}",
                    path.display()
                ))
            })
        })
        .try_fold(Vec::new(), |mut roots, certs| {
            roots.extend(certs?);
            Ok(roots)
        })
}

fn build_root_store(paths: &[std::path::PathBuf]) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in paths {
        let pem = std::fs::read(path).map_err(|error| {
            TransportError::Configuration(format!(
                "read CA certificate {}: {error}",
                path.display()
            ))
        })?;
        let mut reader = io::BufReader::new(pem.as_slice());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                TransportError::Configuration(format!(
                    "parse CA certificate {}: {error}",
                    path.display()
                ))
            })?;
        for certificate in certificates {
            roots.add(certificate).map_err(|error| {
                TransportError::Configuration(format!(
                    "load CA certificate {}: {error}",
                    path.display()
                ))
            })?;
        }
    }
    Ok(roots)
}

fn unbracket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}
