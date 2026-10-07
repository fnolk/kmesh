use std::{
    io::BufReader,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use iroh::{EndpointAddr, RelayUrl, SecretKey};
use iroh_relay::server::{
    CertConfig, QuicConfig as RelayQuicConfig, RelayConfig as RelayHttpConfig,
    Server as RelayServer, ServerConfig as RelayServerConfig, TlsConfig as RelayTlsConfig,
};
use iroh_relay::tls::CaTlsConfig;
use kmesh::{
    config::TlsConfig,
    transport::{
        IrohEndpointOptions, QadReflector, RelayChoice, allowed_relay_urls, create_endpoint,
        observe_ipv4_mappings, validate_endpoint_addr, wait_endpoint_ready,
    },
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivateKeyDer;
use tokio::time::{Instant, timeout};
use uuid::Uuid;

struct TestCertificate(PathBuf);

impl Drop for TestCertificate {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn relay_address_allowlist_is_scoped_to_direct_and_private_modes() {
    let private_url: reqwest::Url = "https://private.kmesh.invalid".parse().unwrap();
    let private_relay = RelayUrl::from(private_url.clone());
    let private_choice = RelayChoice::Private {
        url: private_url,
        quic_port: 3478,
    };
    let endpoint_addr =
        EndpointAddr::new(SecretKey::generate().public()).with_relay_url(private_relay.clone());

    let private_relays = allowed_relay_urls(&private_choice).unwrap();
    assert_eq!(private_relays.len(), 1);
    assert!(private_relays.contains(&private_relay));
    assert!(validate_endpoint_addr(&endpoint_addr, &private_choice).is_ok());

    let direct_relays = allowed_relay_urls(&RelayChoice::DirectOnly).unwrap();
    assert!(direct_relays.is_empty());
    assert!(validate_endpoint_addr(&endpoint_addr, &RelayChoice::DirectOnly).is_err());
}

#[tokio::test]
async fn self_hosted_endpoint_is_relay_only_and_qad_reports_on_its_own_socket() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let certificate = generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let certificate_pem = certificate.cert.pem();
    let key_pem = certificate.signing_key.serialize_pem();
    let ca_path = std::env::temp_dir().join(format!("kmesh-iroh-ca-{}.pem", Uuid::new_v4()));
    std::fs::write(&ca_path, &certificate_pem).unwrap();
    let certificate_file = TestCertificate(ca_path);

    let server_certificates =
        rustls_pemfile::certs(&mut BufReader::new(certificate_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let server_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))
            .unwrap()
            .unwrap();
    let server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_certificates, server_key)
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
    let relay_server = RelayServer::spawn(relay_config).await.unwrap();

    let https_addr = relay_server.https_addr().unwrap();
    let SocketAddr::V4(qad_addr) = relay_server.quic_addr().unwrap() else {
        unreachable!("the self-hosted QAD listener is bound to IPv4 loopback")
    };

    let mut ca_reader = BufReader::new(certificate_pem.as_bytes());
    let ca_certs = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let ca_tls = CaTlsConfig::default().with_extra_roots(ca_certs);
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let qad_tls = ca_tls.client_config(crypto_provider).unwrap();
    let qad_socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let SocketAddr::V4(local_qad_socket) = qad_socket.local_addr().unwrap() else {
        unreachable!("QAD test socket was bound to IPv4 loopback")
    };
    let reflector = QadReflector {
        addr: qad_addr,
        server_name: "127.0.0.1".to_owned(),
    };
    let probe_deadline = Instant::now() + Duration::from_secs(2);
    let cleanup_deadline = Instant::now() + Duration::from_secs(10);
    let (qad_socket, observations) = timeout(
        Duration::from_secs(10),
        observe_ipv4_mappings(
            qad_socket,
            qad_tls,
            &[reflector],
            probe_deadline,
            cleanup_deadline,
        ),
    )
    .await
    .expect("standalone QAD observation completes")
    .expect("self-hosted QAD handshake succeeds");
    assert_eq!(
        qad_socket.local_addr().unwrap(),
        SocketAddr::V4(local_qad_socket)
    );
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.local_socket, local_qad_socket);
    assert_eq!(*observation.observed_addr.ip(), Ipv4Addr::LOCALHOST);
    assert!(observation.handshake_confirmed);
    assert!(observation.udp_tx_datagrams > 0 && observation.udp_rx_datagrams > 0);
    assert!(observation.udp_tx_bytes > 0 && observation.udp_rx_bytes > 0);
    drop(qad_socket);
    let rebound_socket = StdUdpSocket::bind(local_qad_socket)
        .expect("QAD Noq drivers released the original UDP tuple before handoff");
    drop(rebound_socket);

    let relay_url: reqwest::Url = format!("https://127.0.0.1:{}", https_addr.port())
        .parse()
        .unwrap();
    let expected_relay = RelayUrl::from(relay_url.clone());
    let endpoint = create_endpoint(
        SecretKey::generate(),
        true,
        IrohEndpointOptions {
            relay_choice: RelayChoice::Private {
                url: relay_url,
                quic_port: qad_addr.port(),
            },
            tls: TlsConfig {
                ca_certificates: vec![certificate_file.0.clone()],
                server_name: None,
            },
            handoff: None,
        },
    )
    .await
    .unwrap();

    let relay_choice = RelayChoice::Private {
        url: format!("https://127.0.0.1:{}", https_addr.port())
            .parse()
            .unwrap(),
        quic_port: qad_addr.port(),
    };
    timeout(
        Duration::from_secs(10),
        wait_endpoint_ready(
            &endpoint,
            &relay_choice,
            Instant::now() + Duration::from_secs(10),
        ),
    )
    .await
    .expect("self-hosted HTTPS relay registration completes")
    .expect("private endpoint registers with the relay");
    assert_eq!(
        endpoint.addr().relay_urls().cloned().collect::<Vec<_>>(),
        vec![expected_relay],
        "private endpoint publishes only its configured relay"
    );
    assert!(
        endpoint.addr().ip_addrs().next().is_none(),
        "private relay endpoint does not publish IP transports"
    );

    drop(endpoint);
    relay_server.shutdown().await.unwrap();
}
