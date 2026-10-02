use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use kmesh::config::StunConfig;
use kmesh::identity::generate_target_certificate;
use kmesh::transport::{QuicConfig, UdpAttempt, serve_stun};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use uuid::Uuid;

fn attempt_config() -> StunConfig {
    StunConfig {
        servers: Vec::new(),
        udp_bind_address: SocketAddr::from(([0, 0, 0, 0], 0)),
        probe_timeout_millis: 3_000,
    }
}

fn loopback_candidate(candidates: &[SocketAddr]) -> SocketAddr {
    candidates
        .iter()
        .copied()
        .find(|candidate| candidate.ip().is_loopback())
        .expect("loopback interface candidate is gathered")
}

fn cert_der(pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_bytes()))
        .next()
        .expect("target certificate exists")
        .expect("target certificate PEM parses")
        .to_vec()
}

#[tokio::test]
async fn stun_mapping_and_shutdown_use_rtc_stun_wire_format() {
    let reservation = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let stun_addr = reservation.local_addr().unwrap();
    drop(reservation);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(serve_stun(stun_addr, shutdown_rx));
    let mut config = attempt_config();
    config.servers = vec![stun_addr.to_string()];
    config.udp_bind_address = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut attempt = UdpAttempt::bind(config).await.unwrap();
    let candidates = attempt.gather().await.unwrap();
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
    );

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn simultaneous_probe_then_quic_stream_preserves_both_half_closes() {
    let mut client_attempt = UdpAttempt::bind(attempt_config()).await.unwrap();
    let mut target_attempt = UdpAttempt::bind(attempt_config()).await.unwrap();
    let (client_candidates, target_candidates) =
        tokio::join!(client_attempt.gather(), target_attempt.gather());
    let client_peer = loopback_candidate(&client_candidates.unwrap());
    let target_peer = loopback_candidate(&target_candidates.unwrap());
    let session_id = Uuid::new_v4();
    let probe_token = [0x31; 32];
    let client_remote_candidates = [target_peer];
    let target_remote_candidates = [client_peer];

    let (client_probe, target_probe) = tokio::join!(
        client_attempt.probe(
            session_id,
            probe_token,
            &client_remote_candidates,
            Duration::from_secs(3),
        ),
        target_attempt.probe(
            session_id,
            probe_token,
            &target_remote_candidates,
            Duration::from_secs(3),
        )
    );
    let client_probe = client_probe.unwrap();
    let target_probe = target_probe.unwrap();
    assert_eq!(client_probe.peer_addr, target_peer);
    assert_eq!(target_probe.peer_addr, client_peer);

    let target_id = Uuid::new_v4();
    let identity = generate_target_certificate(target_id).unwrap();
    let acceptor = target_attempt
        .into_quic_server(
            target_id,
            &identity.certificate_pem,
            &identity.private_key_pem,
            QuicConfig::default(),
        )
        .unwrap();
    let target_task = tokio::spawn(async move {
        let mut stream = acceptor.accept().await?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        stream.write_all(b"ssh response").await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
    });

    let mut client_stream = client_attempt
        .into_quic_client(
            target_id,
            client_probe.peer_addr,
            cert_der(&identity.certificate_pem),
            &identity.fingerprint,
            QuicConfig::default(),
        )
        .await
        .unwrap();
    client_stream.write_all(b"ssh request").await.unwrap();
    client_stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"ssh response");
    assert_eq!(target_task.await.unwrap().unwrap(), b"ssh request");
}
