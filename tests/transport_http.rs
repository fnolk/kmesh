use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kmesh::config::{HttpProxyConfig, TlsConfig};
use kmesh::transport::{TransportError, connect_wss, http_client};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use uuid::Uuid;

struct LocalCertificate {
    cert_pem: String,
    key_pem: String,
    ca_path: PathBuf,
}

impl Drop for LocalCertificate {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ca_path);
    }
}

fn local_certificate() -> LocalCertificate {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    let ca_path = std::env::temp_dir().join(format!("kmesh-ca-{}.pem", Uuid::new_v4()));
    std::fs::write(&ca_path, &cert_pem).unwrap();
    LocalCertificate {
        cert_pem,
        key_pem,
        ca_path,
    }
}

fn tls_acceptor(identity: &LocalCertificate) -> TlsAcceptor {
    let certificates = rustls_pemfile::certs(&mut io::BufReader::new(identity.cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut io::BufReader::new(identity.key_pem.as_bytes()))
            .unwrap()
            .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

fn proxy_config(scheme: &str, address: SocketAddr) -> HttpProxyConfig {
    HttpProxyConfig {
        url: format!("{scheme}://{address}"),
        username: Some("kmesh-test".to_owned()),
        password: Some("proxy-secret".to_owned()),
    }
}

fn tls_config(identity: &LocalCertificate, proxy: HttpProxyConfig) -> TlsConfig {
    TlsConfig {
        ca_certificates: vec![identity.ca_path.clone()],
        server_name: None,
        proxy: Some(proxy),
    }
}

async fn read_headers<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    loop {
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return bytes;
        }
        assert!(bytes.len() < 16 * 1024, "HTTP headers stay bounded");
    }
}

fn assert_connect_auth(headers: &[u8]) {
    let mut parsed_headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut parsed_headers);
    let httparse::Status::Complete(_) = request.parse(headers).unwrap() else {
        panic!("CONNECT request is complete")
    };
    assert_eq!(request.method, Some("CONNECT"));
    let expected = format!("Basic {}", STANDARD.encode("kmesh-test:proxy-secret"));
    let auth = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("proxy-authorization"))
        .expect("proxy authorization is present");
    assert_eq!(auth.value, expected.as_bytes());
}

async fn proxy_tunnel<S>(mut incoming: S, origin: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let headers = read_headers(&mut incoming).await;
    assert_connect_auth(&headers);
    incoming
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .unwrap();
    let mut upstream = TcpStream::connect(origin).await.unwrap();
    tokio::io::copy_bidirectional(&mut incoming, &mut upstream)
        .await
        .unwrap();
}

async fn start_connect_proxy(
    scheme: &str,
    origin: SocketAddr,
    acceptor: TlsAcceptor,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let secure = scheme == "https";
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if secure {
            proxy_tunnel(acceptor.accept(stream).await.unwrap(), origin).await;
        } else {
            proxy_tunnel(stream, origin).await;
        }
    });
    (address, task)
}

async fn serve_http_origin(listener: TcpListener, acceptor: TlsAcceptor) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut stream = acceptor.accept(stream).await.unwrap();
    let _headers = read_headers(&mut stream).await;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .unwrap();
}

async fn serve_wss_origin(listener: TcpListener, acceptor: TlsAcceptor) {
    let (stream, _) = listener.accept().await.unwrap();
    let stream = acceptor.accept(stream).await.unwrap();
    let mut websocket = accept_async(stream).await.unwrap();
    websocket
        .send(Message::Binary(Bytes::from_static(&[0, b'o', b'k'])))
        .await
        .unwrap();
    websocket
        .send(Message::Binary(Bytes::from_static(&[1])))
        .await
        .unwrap();
    websocket.send(Message::Close(None)).await.unwrap();
    let _ = websocket.next().await;
    websocket.get_mut().shutdown().await.unwrap();
}

async fn reject_wss_origin(listener: TcpListener, acceptor: TlsAcceptor) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut stream = acceptor.accept(stream).await.unwrap();
    let _request = read_headers(&mut stream).await;
    stream
        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
}

#[tokio::test]
async fn rest_and_wss_use_connect_basic_and_enterprise_ca() {
    let identity = local_certificate();
    let acceptor = tls_acceptor(&identity);

    let http_origin = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let http_origin_addr = http_origin.local_addr().unwrap();
    let http_origin_task = tokio::spawn(serve_http_origin(http_origin, acceptor.clone()));
    let (http_proxy_addr, http_proxy_task) =
        start_connect_proxy("http", http_origin_addr, acceptor.clone()).await;
    let http_tls = tls_config(&identity, proxy_config("http", http_proxy_addr));
    let client = http_client(&http_tls).unwrap();
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(format!(
                "https://127.0.0.1:{}/rest",
                http_origin_addr.port()
            ))
            .send(),
    )
    .await
    .expect("REST request completes through CONNECT")
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        timeout(Duration::from_secs(5), response.bytes())
            .await
            .expect("REST response body completes")
            .unwrap(),
        "ok"
    );
    timeout(Duration::from_secs(5), http_proxy_task)
        .await
        .expect("REST proxy tunnel closes")
        .unwrap();
    timeout(Duration::from_secs(5), http_origin_task)
        .await
        .expect("REST origin closes")
        .unwrap();

    let wss_origin = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let wss_origin_addr = wss_origin.local_addr().unwrap();
    let wss_origin_task = tokio::spawn(serve_wss_origin(wss_origin, acceptor.clone()));
    let (wss_proxy_addr, wss_proxy_task) =
        start_connect_proxy("https", wss_origin_addr, acceptor).await;
    let wss_tls = tls_config(&identity, proxy_config("https", wss_proxy_addr));
    let request = format!("wss://127.0.0.1:{}/relay", wss_origin_addr.port())
        .into_client_request()
        .unwrap();
    let mut websocket = timeout(Duration::from_secs(5), connect_wss(request, &wss_tls))
        .await
        .expect("WSS connects through HTTPS CONNECT")
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), websocket.next())
            .await
            .expect("WSS DATA arrives")
            .unwrap()
            .unwrap(),
        Message::Binary(Bytes::from_static(&[0, b'o', b'k']))
    );
    assert_eq!(
        timeout(Duration::from_secs(5), websocket.next())
            .await
            .expect("WSS FIN arrives")
            .unwrap()
            .unwrap(),
        Message::Binary(Bytes::from_static(&[1]))
    );
    assert!(matches!(
        timeout(Duration::from_secs(5), websocket.next())
            .await
            .expect("WSS close arrives")
            .unwrap()
            .unwrap(),
        Message::Close(_)
    ));
    timeout(Duration::from_secs(5), websocket.flush())
        .await
        .expect("WSS close response flushes")
        .unwrap();
    websocket.get_mut().shutdown().await.unwrap();
    drop(websocket);
    timeout(Duration::from_secs(5), wss_proxy_task)
        .await
        .expect("WSS proxy tunnel closes")
        .unwrap();
    timeout(Duration::from_secs(5), wss_origin_task)
        .await
        .expect("WSS origin closes")
        .unwrap();
}

#[tokio::test]
async fn wss_certificate_and_upgrade_authentication_failures_are_classified() {
    let identity = local_certificate();
    let acceptor = tls_acceptor(&identity);

    let untrusted_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let untrusted_addr = untrusted_listener.local_addr().unwrap();
    let untrusted_task = tokio::spawn(async move {
        let (stream, _) = untrusted_listener.accept().await.unwrap();
        let _ = acceptor.accept(stream).await;
    });
    let request = format!("wss://127.0.0.1:{}/relay", untrusted_addr.port())
        .into_client_request()
        .unwrap();
    let untrusted_tls = TlsConfig::default();
    let error = connect_wss(request, &untrusted_tls)
        .await
        .err()
        .expect("untrusted WSS certificate fails");
    assert!(matches!(error, TransportError::Authentication(_)));
    untrusted_task.await.unwrap();

    let identity = local_certificate();
    let acceptor = tls_acceptor(&identity);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(reject_wss_origin(listener, acceptor));
    let request = format!("wss://127.0.0.1:{}/relay", address.port())
        .into_client_request()
        .unwrap();
    let trusted_tls = TlsConfig {
        ca_certificates: vec![identity.ca_path.clone()],
        server_name: None,
        proxy: None,
    };
    let error = connect_wss(request, &trusted_tls)
        .await
        .err()
        .expect("WSS authorization rejection fails");
    assert!(matches!(error, TransportError::Authentication(_)));
    server.await.unwrap();
}
