use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use iroh::{RelayUrl, SecretKey, Watcher as _};
use iroh_relay::{
    client::ClientBuilder,
    server::{
        CertConfig, QuicConfig as RelayQuicConfig, RelayConfig as RelayHttpConfig,
        Server as RelayServer, ServerConfig as RelayServerConfig, TlsConfig as RelayTlsConfig,
    },
    tls::CaTlsConfig,
};
use kmesh::config::{HttpProxyConfig, TlsConfig};
use kmesh::transport::{
    IrohByteStream, IrohEndpointOptions, RelayChoice, TransportError, accept_peer, connect_peer,
    connect_wss, create_endpoint, http_client, is_auth_failure_source, is_network_failure_source,
    wait_endpoint_ready, wait_for_selected_path,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};
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

async fn proxy_tunnel<S>(
    mut incoming: S,
    origin: SocketAddr,
    mut application_exchange_complete: watch::Receiver<bool>,
) -> io::Result<()>
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
    match tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            while !*application_exchange_complete.borrow() {
                if application_exchange_complete.changed().await.is_err() {
                    return Err(error);
                }
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn start_connect_proxy(
    scheme: &str,
    origin: SocketAddr,
    acceptor: TlsAcceptor,
) -> (SocketAddr, tokio::task::JoinHandle<()>, watch::Sender<bool>) {
    start_connect_proxy_with_connections(scheme, origin, acceptor, 1).await
}

async fn start_connect_proxy_with_connections(
    scheme: &str,
    origin: SocketAddr,
    acceptor: TlsAcceptor,
    connection_count: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>, watch::Sender<bool>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let secure = scheme == "https";
    let (application_exchange_complete, task_application_exchange_complete) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut tunnels = JoinSet::new();
        for _ in 0..connection_count {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let application_exchange_complete = task_application_exchange_complete.clone();
            tunnels.spawn(async move {
                if secure {
                    proxy_tunnel(
                        acceptor.accept(stream).await.unwrap(),
                        origin,
                        application_exchange_complete,
                    )
                    .await
                    .unwrap();
                } else {
                    proxy_tunnel(stream, origin, application_exchange_complete)
                        .await
                        .unwrap();
                }
            });
        }
        while let Some(result) = tunnels.join_next().await {
            result.unwrap();
        }
    });
    (address, task, application_exchange_complete)
}

async fn start_rejecting_connect_proxy(
    scheme: &str,
    acceptor: TlsAcceptor,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let secure = scheme == "https";
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream: Box<dyn AsyncReadWrite> = if secure {
            Box::new(acceptor.accept(stream).await.unwrap())
        } else {
            Box::new(stream)
        };
        let headers = read_headers(&mut stream).await;
        assert_connect_auth(&headers);
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    (address, task)
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn start_local_relay(identity: &LocalCertificate) -> (RelayServer, SocketAddr, u16) {
    let certificates = rustls_pemfile::certs(&mut io::BufReader::new(identity.cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut io::BufReader::new(identity.key_pem.as_bytes()))
            .unwrap()
            .unwrap();
    let server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
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
    let quic_port = server.quic_addr().unwrap().port();
    (server, https_addr, quic_port)
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
    let (http_proxy_addr, http_proxy_task, http_exchange_complete) =
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
    timeout(Duration::from_secs(5), http_origin_task)
        .await
        .expect("REST origin closes")
        .unwrap();
    http_exchange_complete.send_replace(true);
    timeout(Duration::from_secs(5), http_proxy_task)
        .await
        .expect("REST proxy tunnel closes")
        .unwrap();

    let wss_origin = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let wss_origin_addr = wss_origin.local_addr().unwrap();
    let wss_origin_task = tokio::spawn(serve_wss_origin(wss_origin, acceptor.clone()));
    let (wss_proxy_addr, wss_proxy_task, wss_exchange_complete) =
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
    timeout(Duration::from_secs(5), wss_origin_task)
        .await
        .expect("WSS origin closes after the Close response")
        .unwrap();
    wss_exchange_complete.send_replace(true);
    websocket.get_mut().shutdown().await.unwrap();
    drop(websocket);
    timeout(Duration::from_secs(5), wss_proxy_task)
        .await
        .expect("WSS proxy tunnel closes")
        .unwrap();
}

#[tokio::test]
async fn iroh_private_relay_carries_ssh_bytes_through_http_and_https_connect() {
    let identity = local_certificate();
    let (relay_server, relay_https_addr, relay_quic_port) = start_local_relay(&identity).await;
    let relay_url: reqwest::Url = format!("https://127.0.0.1:{}", relay_https_addr.port())
        .parse()
        .unwrap();
    let relay_choice = RelayChoice::Private {
        url: relay_url.clone(),
        quic_port: relay_quic_port,
    };
    let request = b"SSH-2.0-kmesh-proxy\r\nexec: uname -a\r\n";
    let response = b"OpenSSH_9.9 exit-status=0\r\n";
    // Iroh allows 5s for the first net report and 10s for the relay handshake, plus 3s to schedule both.
    let registration_timeout = Duration::from_secs(iroh::NET_REPORT_TIMEOUT + 13);

    for scheme in ["http", "https"] {
        let acceptor = tls_acceptor(&identity);
        let (client_proxy_addr, client_proxy_task, client_exchange_complete) =
            start_connect_proxy_with_connections(scheme, relay_https_addr, acceptor.clone(), 2)
                .await;
        let (agent_proxy_addr, agent_proxy_task, agent_exchange_complete) =
            start_connect_proxy_with_connections(scheme, relay_https_addr, acceptor, 2).await;
        let client_tls = tls_config(&identity, proxy_config(scheme, client_proxy_addr));
        let agent_tls = tls_config(&identity, proxy_config(scheme, agent_proxy_addr));

        let client = create_endpoint(
            SecretKey::generate(),
            true,
            IrohEndpointOptions {
                relay_choice: relay_choice.clone(),
                tls: client_tls,
                handoff: None,
            },
        )
        .await
        .unwrap();
        let agent = create_endpoint(
            SecretKey::generate(),
            false,
            IrohEndpointOptions {
                relay_choice: relay_choice.clone(),
                tls: agent_tls,
                handoff: None,
            },
        )
        .await
        .unwrap();
        for endpoint in [&client, &agent] {
            let readiness = timeout(
                registration_timeout,
                wait_endpoint_ready(
                    endpoint,
                    &relay_choice,
                    Instant::now() + registration_timeout,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "private relay registration timed out; home relay status: {:?}",
                    endpoint.home_relay_status().get()
                )
            });
            if let Err(error) = readiness {
                panic!(
                    "private relay registration failed: {error:?}; home relay status: {:?}",
                    endpoint.home_relay_status().get()
                );
            }
        }

        let client_addr = client.addr();
        let accepting_endpoint = client.clone();
        let target = tokio::spawn(async move {
            let connection = accept_peer(&accepting_endpoint)
                .await
                .expect("client accepts the QUIC connection");
            let selected_path = wait_for_selected_path(
                &connection,
                kmesh::protocol::RouteMode::PrivateRelay,
                Instant::now() + Duration::from_secs(8),
            )
            .await
            .expect("client selected the private relay path");
            assert!(matches!(
                selected_path,
                kmesh::protocol::SelectedPath::PrivateRelay { .. }
            ));
            let mut stream = IrohByteStream::accept_bi(connection)
                .await
                .expect("client accepts the SSH-shaped stream");
            let mut received = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut received)
                .await
                .expect("read SSH request through private relay");
            assert_eq!(received, request);
            tokio::io::AsyncWriteExt::write_all(&mut stream, response)
                .await
                .expect("write SSH reply through private relay");
            stream
                .finish_send_and_wait()
                .await
                .expect("private relay acknowledges SSH reply bytes");
        });

        let connection = timeout(
            Duration::from_secs(8),
            connect_peer(&agent, client_addr, &relay_choice),
        )
        .await
        .expect("agent connects through the private relay")
        .expect("Iroh connection uses the private relay");
        let selected_path = wait_for_selected_path(
            &connection,
            kmesh::protocol::RouteMode::PrivateRelay,
            Instant::now() + Duration::from_secs(8),
        )
        .await
        .expect("agent selected the private relay path");
        assert!(matches!(
            selected_path,
            kmesh::protocol::SelectedPath::PrivateRelay { .. }
        ));
        let mut stream = IrohByteStream::open_bi(connection)
            .await
            .expect("agent opens the SSH-shaped stream");
        tokio::io::AsyncWriteExt::write_all(&mut stream, request)
            .await
            .expect("write SSH request through private relay");
        stream
            .finish_send_and_wait()
            .await
            .expect("private relay acknowledges SSH request bytes");
        let mut received = Vec::new();
        timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut received),
        )
        .await
        .expect("SSH reply arrives through private relay")
        .expect("read SSH reply through private relay");
        assert_eq!(received, response);
        drop(stream);
        target.await.unwrap();

        client_exchange_complete.send_replace(true);
        agent_exchange_complete.send_replace(true);
        client.close().await;
        agent.close().await;
        timeout(Duration::from_secs(5), client_proxy_task)
            .await
            .expect("client CONNECT proxy closes")
            .unwrap();
        timeout(Duration::from_secs(5), agent_proxy_task)
            .await
            .expect("agent CONNECT proxy closes")
            .unwrap();
    }

    relay_server.shutdown().await.unwrap();
}

#[tokio::test]
async fn iroh_relay_rejects_untrusted_ca_and_proxy_407_as_authentication_failures() {
    let identity = local_certificate();
    let (relay_server, relay_https_addr, _relay_quic_port) = start_local_relay(&identity).await;
    let relay_url: reqwest::Url = format!("https://127.0.0.1:{}", relay_https_addr.port())
        .parse()
        .unwrap();
    let (proxy_addr, proxy_task, application_exchange_complete) =
        start_connect_proxy("http", relay_https_addr, tls_acceptor(&identity)).await;
    let mut proxy_url: reqwest::Url = format!("http://{proxy_addr}").parse().unwrap();
    proxy_url.set_username("kmesh-test").unwrap();
    proxy_url.set_password(Some("proxy-secret")).unwrap();
    let untrusted_tls = CaTlsConfig::default()
        .client_config(Arc::new(rustls::crypto::ring::default_provider()))
        .unwrap();
    let untrusted_error = timeout(
        Duration::from_secs(5),
        ClientBuilder::new(
            RelayUrl::from(relay_url.clone()),
            SecretKey::generate(),
            Default::default(),
        )
        .tls_client_config(untrusted_tls)
        .proxy_url(proxy_url)
        .connect(),
    )
    .await
    .expect("untrusted relay TLS fails promptly")
    .expect_err("self-signed relay certificate requires the configured CA");
    assert!(is_auth_failure_source(&untrusted_error));
    assert!(!is_network_failure_source(&untrusted_error));
    application_exchange_complete.send_replace(true);
    timeout(Duration::from_secs(5), proxy_task)
        .await
        .expect("untrusted relay CONNECT tunnel closes")
        .unwrap();

    let acceptor = tls_acceptor(&identity);
    let (proxy_addr, proxy_task) = start_rejecting_connect_proxy("https", acceptor).await;
    let mut proxy_url: reqwest::Url = format!("https://{proxy_addr}").parse().unwrap();
    proxy_url.set_username("kmesh-test").unwrap();
    proxy_url.set_password(Some("proxy-secret")).unwrap();
    let trusted_tls = CaTlsConfig::default()
        .with_extra_roots(
            rustls_pemfile::certs(&mut io::BufReader::new(identity.cert_pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        )
        .client_config(Arc::new(rustls::crypto::ring::default_provider()))
        .unwrap();
    let proxy_error = timeout(
        Duration::from_secs(5),
        ClientBuilder::new(
            RelayUrl::from(relay_url),
            SecretKey::generate(),
            Default::default(),
        )
        .tls_client_config(trusted_tls)
        .proxy_url(proxy_url)
        .connect(),
    )
    .await
    .expect("proxy rejection is returned promptly")
    .expect_err("HTTP 407 is a proxy authentication failure");
    assert!(is_auth_failure_source(&proxy_error));
    assert!(!is_network_failure_source(&proxy_error));
    timeout(Duration::from_secs(5), proxy_task)
        .await
        .expect("HTTP 407 proxy closes")
        .unwrap();

    relay_server.shutdown().await.unwrap();
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
