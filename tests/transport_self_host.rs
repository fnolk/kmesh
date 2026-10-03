use std::{io::BufReader, net::SocketAddr, path::PathBuf, time::Duration};

use iroh::{EndpointAddr, RelayUrl, SecretKey, Watcher, unstable_net_report::Probe};
use iroh_relay::server::{
    CertConfig, QuicConfig as RelayQuicConfig, RelayConfig as RelayHttpConfig,
    Server as RelayServer, ServerConfig as RelayServerConfig, TlsConfig as RelayTlsConfig,
};
use kmesh::{
    config::TlsConfig,
    transport::{
        IrohEndpointOptions, RelayChoice, allowed_relay_urls, create_endpoint,
        validate_endpoint_addr,
    },
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivateKeyDer;
use tokio::time::timeout;
use uuid::Uuid;

struct TestCertificate(PathBuf);

impl Drop for TestCertificate {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn relay_address_allowlist_is_scoped_to_the_selected_mode() {
    let private_url: reqwest::Url = "https://private.kmesh.invalid".parse().unwrap();
    let private_relay = RelayUrl::from(private_url.clone());
    let private_choice = RelayChoice::Private {
        url: private_url,
        qad_port: 3478,
    };
    let endpoint_addr =
        EndpointAddr::new(SecretKey::generate().public()).with_relay_url(private_relay.clone());

    let private_relays = allowed_relay_urls(&private_choice).unwrap();
    assert_eq!(private_relays.len(), 1);
    assert!(private_relays.contains(&private_relay));
    assert!(validate_endpoint_addr(&endpoint_addr, &private_choice).is_ok());

    let official_relays = allowed_relay_urls(&RelayChoice::PublicDefault).unwrap();
    assert!(!official_relays.is_empty());
    assert!(!official_relays.contains(&private_relay));
    assert!(validate_endpoint_addr(&endpoint_addr, &RelayChoice::PublicDefault).is_err());
}

#[tokio::test]
async fn self_hosted_https_and_qad_report_the_observed_ipv4_address() {
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
    let qad_addr = relay_server.quic_addr().unwrap();
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
                qad_port: qad_addr.port(),
            },
            tls: TlsConfig {
                ca_certificates: vec![certificate_file.0.clone()],
                server_name: None,
                proxy: None,
            },
        },
    )
    .await
    .unwrap();

    timeout(Duration::from_secs(10), endpoint.online())
        .await
        .expect("self-hosted HTTPS relay connection completes");
    let mut report_watcher = endpoint.net_report();
    let report = timeout(Duration::from_secs(15), report_watcher.initialized())
        .await
        .expect("self-hosted QAD probe completes");

    assert!(report.udp_v4, "QAD IPv4 probe completed");
    assert_eq!(report.global_v4.unwrap().ip().to_string(), "127.0.0.1");
    assert!(report.preferred_relay.as_ref() == Some(&expected_relay));
    assert!(
        report
            .relay_latency
            .iter()
            .any(|(probe, url, _)| { probe == Probe::Https && url == &expected_relay })
    );
    assert!(
        report
            .relay_latency
            .iter()
            .any(|(probe, url, _)| { probe == Probe::QadIpv4 && url == &expected_relay })
    );
    assert_eq!(
        endpoint.addr().relay_urls().cloned().collect::<Vec<_>>(),
        vec![expected_relay],
        "private endpoint publishes only its configured relay"
    );

    drop(endpoint);
    relay_server.shutdown().await.unwrap();
}
