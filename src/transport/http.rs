use std::io;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{WebSocketStream, client_async_with_config};

use crate::transport::{TransportError, ensure_rustls_provider};

const NETWORK_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const WSS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub type WsStream = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Build the REST client with the embedded kmesh identity and direct connections.
pub fn http_client() -> Result<reqwest::Client, TransportError> {
    ensure_rustls_provider();
    reqwest::Client::builder()
        .no_proxy()
        .tls_backend_preconfigured(super::tls::private_client_config()?)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(NETWORK_CONNECT_TIMEOUT)
        .timeout(NETWORK_CONNECT_TIMEOUT)
        .build()
        .map_err(|error| TransportError::Tls(format!("build REST TLS client: {error}")))
}

/// Connect a WSS request directly.
pub async fn connect_wss<R>(request: R) -> Result<WsStream, TransportError>
where
    R: IntoClientRequest + Unpin,
{
    tokio::time::timeout(WSS_HANDSHAKE_TIMEOUT, connect_wss_inner(request))
        .await
        .map_err(|_| TransportError::Timeout("WSS connection and handshake"))?
}

async fn connect_wss_inner<R>(request: R) -> Result<WsStream, TransportError>
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
    let config = Arc::new(super::tls::private_client_config()?);
    let server_name = ServerName::try_from(socket_host.to_owned()).map_err(|error| {
        TransportError::Configuration(format!("invalid WSS server host: {error}"))
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

fn unbracket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}
