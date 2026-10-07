use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use iroh::{RelayUrl, SecretKey};
use iroh_relay::{
    client::ClientBuilder,
    server::{
        CertConfig, QuicConfig as RelayQuicConfig, RelayConfig as RelayHttpConfig,
        Server as RelayServer, ServerConfig as RelayServerConfig, TlsConfig as RelayTlsConfig,
    },
};
use kmesh::transport::{
    TransportError, connect_wss, http_client, is_auth_failure_source, is_network_failure_source,
    tls::private_ca_tls_config,
};
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::PrivateKeyDer,
    server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

struct LocalCertificate {
    cert_pem: String,
    key_pem: String,
}

fn local_certificate() -> LocalCertificate {
    ensure_crypto_provider();
    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    LocalCertificate {
        cert_pem: cert.cert.pem(),
        key_pem: cert.signing_key.serialize_pem(),
    }
}

fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

fn configured_pem(env_name: &str) -> Vec<u8> {
    std::fs::read(std::env::var(env_name).unwrap_or_else(|_| panic!("{env_name} is required")))
        .unwrap_or_else(|error| panic!("read {env_name}: {error}"))
}

fn parse_certificates(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    rustls_pemfile::certs(&mut io::BufReader::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn parse_private_key(pem: &[u8]) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut io::BufReader::new(pem))
        .unwrap()
        .unwrap()
}

fn embedded_server_config() -> rustls::ServerConfig {
    embedded_server_config_with_sni_observer(None)
}

fn embedded_server_config_with_sni_observer(
    sni_observer: Option<Arc<std::sync::Mutex<Vec<Option<String>>>>>,
) -> rustls::ServerConfig {
    ensure_crypto_provider();
    let ca = parse_certificates(&configured_pem("KMESH_CA_CERT_PATH"));
    let mut roots = RootCertStore::empty();
    for certificate in ca {
        roots.add(certificate).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let certificate_chain = parse_certificates(&configured_pem("KMESH_SERVER_CERT_PATH"));
    let private_key = parse_private_key(&configured_pem("KMESH_SERVER_KEY_PATH"));
    let builder = rustls::ServerConfig::builder().with_client_cert_verifier(verifier);
    match sni_observer {
        Some(sni_observer) => {
            let certified_key = CertifiedKey::from_der(
                certificate_chain,
                private_key,
                &rustls::crypto::ring::default_provider(),
            )
            .unwrap();
            builder.with_cert_resolver(Arc::new(RecordingCertResolver {
                certified_key: Arc::new(certified_key),
                sni_observer,
            }))
        }
        None => builder
            .with_single_cert(certificate_chain, private_key)
            .unwrap(),
    }
}

#[derive(Debug)]
struct RecordingCertResolver {
    certified_key: Arc<CertifiedKey>,
    sni_observer: Arc<std::sync::Mutex<Vec<Option<String>>>>,
}

impl ResolvesServerCert for RecordingCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.sni_observer
            .lock()
            .unwrap()
            .push(client_hello.server_name().map(str::to_owned));
        Some(self.certified_key.clone())
    }
}

fn untrusted_server_config(identity: &LocalCertificate) -> rustls::ServerConfig {
    ensure_crypto_provider();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            parse_certificates(identity.cert_pem.as_bytes()),
            parse_private_key(identity.key_pem.as_bytes()),
        )
        .unwrap()
}

fn tls_acceptor(config: rustls::ServerConfig) -> TlsAcceptor {
    let mut config = config;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
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

async fn start_local_relay(server_tls: rustls::ServerConfig) -> (RelayServer, SocketAddr) {
    let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut relay_http = RelayHttpConfig::new(loopback);
    relay_http.tls = Some(RelayTlsConfig::new(
        loopback,
        CertConfig::Manual {
            server_config: server_tls.clone(),
        },
    ));
    let mut relay_quic = RelayQuicConfig::new(loopback);
    relay_quic.server_config = Some(server_tls);
    let mut relay_config = RelayServerConfig::default();
    relay_config.relay = Some(relay_http);
    relay_config.quic = Some(relay_quic);
    let server = RelayServer::spawn(relay_config).await.unwrap();
    let https_addr = server.https_addr().unwrap();
    (server, https_addr)
}

async fn serve_http_origin(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    request_count: usize,
) -> Vec<(Option<String>, String)> {
    let mut requests = Vec::with_capacity(request_count);
    for _ in 0..request_count {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let server_name = stream.get_ref().1.server_name().map(str::to_owned);
        let headers = read_headers(&mut stream).await;
        let headers = String::from_utf8(headers).unwrap();
        let host = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("host")
                    .then(|| value.trim().to_owned())
            })
            .expect("HTTP request carries its destination host");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        requests.push((server_name, host));
    }
    requests
}

async fn serve_wss_origin(listener: TcpListener, acceptor: TlsAcceptor) -> Option<String> {
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
    let server_name = websocket
        .get_ref()
        .get_ref()
        .1
        .server_name()
        .map(str::to_owned);
    websocket.get_mut().shutdown().await.unwrap();
    server_name
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
async fn rest_and_wss_use_the_embedded_mtls_identity_over_direct_connections() {
    let acceptor = tls_acceptor(embedded_server_config());

    let http_origin = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let http_origin_addr = http_origin.local_addr().unwrap();
    let http_origin_task = tokio::spawn(serve_http_origin(http_origin, acceptor.clone(), 2));
    let client = http_client().unwrap();
    for host in ["localhost", "127.0.0.1"] {
        let response = timeout(
            Duration::from_secs(5),
            client
                .get(format!("https://{host}:{}/rest", http_origin_addr.port()))
                .send(),
        )
        .await
        .expect("REST request completes")
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap(), "ok");
    }
    let server_requests = timeout(Duration::from_secs(5), http_origin_task)
        .await
        .expect("REST origin closes")
        .unwrap();
    assert_eq!(
        server_requests,
        vec![
            (None, format!("localhost:{}", http_origin_addr.port())),
            (None, format!("127.0.0.1:{}", http_origin_addr.port())),
        ],
        "REST preserves each URL host while private mTLS omits SNI"
    );

    let wss_origin = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let wss_origin_addr = wss_origin.local_addr().unwrap();
    let wss_origin_task = tokio::spawn(serve_wss_origin(wss_origin, acceptor));
    let request = format!("wss://localhost:{}/relay", wss_origin_addr.port())
        .into_client_request()
        .unwrap();
    let mut websocket = timeout(Duration::from_secs(5), connect_wss(request))
        .await
        .expect("WSS connection completes")
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
    websocket.flush().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), wss_origin_task)
            .await
            .expect("WSS origin closes after the Close response")
            .unwrap(),
        None,
        "WSS private mTLS omits the network host from TLS SNI"
    );
}

#[tokio::test]
async fn private_iroh_relay_uses_mtls_and_rejects_a_wrong_ca() {
    ensure_crypto_provider();
    let sni_observer = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (relay_server, relay_https_addr) = start_local_relay(
        embedded_server_config_with_sni_observer(Some(sni_observer.clone())),
    )
    .await;
    let relay_url = RelayUrl::from(
        format!("https://localhost:{}", relay_https_addr.port())
            .parse::<reqwest::Url>()
            .unwrap(),
    );
    let client_tls = private_ca_tls_config()
        .unwrap()
        .client_config(Arc::new(rustls::crypto::ring::default_provider()))
        .unwrap();
    timeout(
        Duration::from_secs(5),
        ClientBuilder::new(relay_url, SecretKey::generate(), Default::default())
            .tls_client_config(client_tls)
            .connect(),
    )
    .await
    .expect("mTLS relay connect completes")
    .expect("embedded client certificate authenticates to the private relay");
    let observed_sni = sni_observer.lock().unwrap().clone();
    assert!(!observed_sni.is_empty(), "relay received a TLS ClientHello");
    assert!(
        observed_sni.iter().all(Option::is_none),
        "private relay handshake omits SNI: {observed_sni:?}"
    );
    relay_server.shutdown().await.unwrap();

    let identity = local_certificate();
    let (relay_server, relay_https_addr) =
        start_local_relay(untrusted_server_config(&identity)).await;
    let relay_url = RelayUrl::from(
        format!("https://127.0.0.1:{}", relay_https_addr.port())
            .parse::<reqwest::Url>()
            .unwrap(),
    );
    let client_tls = private_ca_tls_config()
        .unwrap()
        .client_config(Arc::new(rustls::crypto::ring::default_provider()))
        .unwrap();
    let error = timeout(
        Duration::from_secs(5),
        ClientBuilder::new(relay_url, SecretKey::generate(), Default::default())
            .tls_client_config(client_tls)
            .connect(),
    )
    .await
    .expect("untrusted relay TLS fails promptly")
    .expect_err("server certificate must chain to the embedded CA");
    assert!(is_auth_failure_source(&error));
    assert!(!is_network_failure_source(&error));
    relay_server.shutdown().await.unwrap();
}

#[tokio::test]
async fn wss_certificate_and_upgrade_authentication_failures_are_classified() {
    let identity = local_certificate();
    let acceptor = tls_acceptor(untrusted_server_config(&identity));
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
    let error = connect_wss(request)
        .await
        .expect_err("untrusted WSS certificate fails");
    assert!(matches!(error, TransportError::Authentication(_)));
    untrusted_task.await.unwrap();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(reject_wss_origin(
        listener,
        tls_acceptor(embedded_server_config()),
    ));
    let request = format!("wss://127.0.0.1:{}/relay", address.port())
        .into_client_request()
        .unwrap();
    let error = connect_wss(request)
        .await
        .expect_err("WSS authorization rejection fails");
    assert!(matches!(error, TransportError::Authentication(_)));
    server.await.unwrap();
}
