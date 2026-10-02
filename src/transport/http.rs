use std::io;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{WebSocketStream, client_async_with_config};

use crate::config::{HttpProxyConfig, TlsConfig};
use crate::transport::{TransportError, ensure_rustls_provider};

const NETWORK_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const WSS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

pub type BoxedIo = Box<dyn AsyncReadWrite + Send + Unpin>;
pub type WsStream = WebSocketStream<BoxedIo>;

/// Build the REST client using the same explicit proxy and trust roots as WSS.
pub fn http_client(tls: &TlsConfig) -> Result<reqwest::Client, TransportError> {
    ensure_rustls_provider();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .tls_backend_rustls()
        .connect_timeout(NETWORK_CONNECT_TIMEOUT)
        .timeout(NETWORK_CONNECT_TIMEOUT);

    if let Some(proxy_config) = &tls.proxy {
        validate_proxy_url(&proxy_config.url)?;
        let mut proxy = reqwest::Proxy::all(&proxy_config.url).map_err(|error| {
            TransportError::Configuration(format!("invalid HTTP proxy URL: {error}"))
        })?;
        match (&proxy_config.username, &proxy_config.password) {
            (Some(username), Some(password)) => {
                proxy = proxy.basic_auth(username, password);
            }
            (None, None) => {}
            _ => {
                return Err(TransportError::Configuration(
                    "HTTP proxy username and password must be configured together".to_owned(),
                ));
            }
        }
        builder = builder.proxy(proxy);
    }

    let certificates = load_reqwest_roots(&tls.ca_certificates)?;
    if !certificates.is_empty() {
        builder = builder.tls_certs_merge(certificates);
    }

    builder
        .build()
        .map_err(|error| TransportError::Tls(format!("build REST TLS client: {error}")))
}

/// Connect a WSS request through a direct or HTTP/HTTPS CONNECT path.
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
    let authority = format_authority(host, port);
    let mut stream: BoxedIo = if let Some(proxy) = &tls.proxy {
        connect_proxy_tunnel(proxy, &authority, tls).await?
    } else {
        let socket = TcpStream::connect((socket_host, port))
            .await
            .map_err(TransportError::Network)?;
        socket.set_nodelay(true).map_err(TransportError::Network)?;
        Box::new(socket)
    };

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
    stream = Box::new(
        TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .map_err(|error| classify_tls_error(error, "WSS TLS handshake"))?,
    );

    let (websocket, _response) =
        client_async_with_config(request, stream, Some(WebSocketConfig::default()))
            .await
            .map_err(map_websocket_handshake_error)?;
    Ok(websocket)
}

async fn connect_proxy_tunnel(
    proxy: &HttpProxyConfig,
    destination: &str,
    tls: &TlsConfig,
) -> Result<BoxedIo, TransportError> {
    validate_proxy_url(&proxy.url)?;
    let proxy_url = reqwest::Url::parse(&proxy.url)
        .map_err(|error| TransportError::Configuration(format!("invalid proxy URL: {error}")))?;
    let proxy_scheme = proxy_url.scheme();
    if !matches!(proxy_scheme, "http" | "https") {
        return Err(TransportError::Configuration(
            "proxy URL scheme must be http or https".to_owned(),
        ));
    }
    if proxy_url.path() != "/" || proxy_url.query().is_some() || proxy_url.fragment().is_some() {
        return Err(TransportError::Configuration(
            "proxy URL must identify an origin without path, query, or fragment".to_owned(),
        ));
    }
    let host = proxy_url
        .host_str()
        .ok_or_else(|| TransportError::Configuration("proxy URL has no host".to_owned()))?;
    let socket_host = unbracket_host(host);
    let port = proxy_url
        .port_or_known_default()
        .ok_or_else(|| TransportError::Configuration("proxy URL has no port".to_owned()))?;
    let socket = TcpStream::connect((socket_host, port))
        .await
        .map_err(TransportError::Network)?;
    socket.set_nodelay(true).map_err(TransportError::Network)?;
    let mut stream: BoxedIo = if proxy_scheme == "https" {
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(build_root_store(&tls.ca_certificates)?)
                .with_no_client_auth(),
        );
        let proxy_name = ServerName::try_from(socket_host.to_owned()).map_err(|error| {
            TransportError::Configuration(format!("invalid proxy TLS server name: {error}"))
        })?;
        Box::new(
            TlsConnector::from(config)
                .connect(proxy_name, socket)
                .await
                .map_err(|error| classify_tls_error(error, "HTTPS proxy TLS handshake"))?,
        )
    } else {
        Box::new(socket)
    };

    let mut connect_request = format!(
        "CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    match (&proxy.username, &proxy.password) {
        (Some(username), Some(password)) => {
            let encoded = STANDARD.encode(format!("{username}:{password}"));
            connect_request.push_str("Proxy-Authorization: Basic ");
            connect_request.push_str(&encoded);
            connect_request.push_str("\r\n");
        }
        (None, None) => {}
        _ => {
            return Err(TransportError::Configuration(
                "HTTP proxy username and password must be configured together".to_owned(),
            ));
        }
    }
    connect_request.push_str("\r\n");
    stream
        .write_all(connect_request.as_bytes())
        .await
        .map_err(TransportError::Network)?;
    stream.flush().await.map_err(TransportError::Network)?;
    let status = read_connect_response(&mut stream).await?;
    if !(200..300).contains(&status) {
        if status == 407 {
            return Err(TransportError::Authentication(
                "HTTP proxy rejected CONNECT credentials".to_owned(),
            ));
        }
        return Err(TransportError::ProtocolViolation(format!(
            "proxy rejected CONNECT with HTTP status {status}"
        )));
    }
    Ok(stream)
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

pub(crate) fn validate_proxy_url(proxy_url: &str) -> Result<reqwest::Url, TransportError> {
    let proxy_url = reqwest::Url::parse(proxy_url)
        .map_err(|error| TransportError::Configuration(format!("invalid proxy URL: {error}")))?;
    if !matches!(proxy_url.scheme(), "http" | "https") {
        return Err(TransportError::Configuration(
            "proxy URL scheme must be http or https".to_owned(),
        ));
    }
    if !proxy_url.username().is_empty() || proxy_url.password().is_some() {
        return Err(TransportError::Configuration(
            "proxy URL credentials must use the separate username/password settings".to_owned(),
        ));
    }
    if proxy_url.path() != "/" || proxy_url.query().is_some() || proxy_url.fragment().is_some() {
        return Err(TransportError::Configuration(
            "proxy URL must identify an origin without path, query, or fragment".to_owned(),
        ));
    }
    Ok(proxy_url)
}

async fn read_connect_response(stream: &mut BoxedIo) -> Result<u16, TransportError> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut bytes = Vec::with_capacity(256);
    let mut byte = [0; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(TransportError::Network)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(TransportError::ProtocolViolation(
                "CONNECT response headers exceed 16 KiB".to_owned(),
            ));
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(&bytes).map_err(|error| {
        TransportError::ProtocolViolation(format!("invalid CONNECT response: {error}"))
    })? {
        httparse::Status::Complete(_) => response.code.ok_or_else(|| {
            TransportError::ProtocolViolation("CONNECT response has no status".to_owned())
        }),
        httparse::Status::Partial => Err(TransportError::ProtocolViolation(
            "CONNECT response headers are incomplete".to_owned(),
        )),
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

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn unbracket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}
