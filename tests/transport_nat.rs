use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use kmesh::config::StunConfig;
use kmesh::identity::generate_target_certificate;
use kmesh::transport::{QuicConfig, UdpAttempt, serve_stun};
use rtc_stun::fingerprint::FINGERPRINT;
use rtc_stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message};
use rtc_stun::xoraddr::XorMappedAddress;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;
use uuid::Uuid;

async fn reserve_loopback_udp_addr() -> SocketAddr {
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    socket.local_addr().unwrap()
}

async fn start_simulated_stun_server(
    ip: Ipv4Addr,
    mapped_port_offset: i16,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(ip), 0))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    match changed {
                        Ok(()) if *shutdown_rx.borrow_and_update() => return Ok(()),
                        Ok(()) => {}
                        Err(_) => return Ok(()),
                    }
                }
                received = socket.recv_from(&mut buffer) => {
                    let (length, source) = received?;
                    if !rtc_stun::message::is_stun_message(&buffer[..length]) {
                        continue;
                    }
                    let mut request = Message::new();
                    if request.unmarshal_binary(&buffer[..length]).is_err()
                        || request.typ != BINDING_REQUEST
                    {
                        continue;
                    }
                    let mapped_port = source.port().checked_add_signed(mapped_port_offset)
                        .expect("simulated mapped port remains in range");
                    let mut response = Message::new();
                    response.build(&[
                        Box::new(request.transaction_id),
                        Box::new(BINDING_SUCCESS),
                        Box::new(XorMappedAddress { ip: source.ip(), port: mapped_port }),
                        Box::new(FINGERPRINT),
                    ]).unwrap();
                    socket.send_to(&response.raw, source).await?;
                }
            }
        }
    });
    (address, shutdown_tx, task)
}

async fn bind_attempt_with_stale_mapping(ip: Ipv4Addr) -> (UdpAttempt, SocketAddr, UdpSocket) {
    loop {
        let mut attempt = UdpAttempt::bind(StunConfig {
            servers: Vec::new(),
            udp_bind_address: SocketAddr::new(IpAddr::V4(ip), 0),
            probe_timeout_millis: 2_000,
        })
        .await
        .unwrap();
        let candidates = attempt.gather().await.unwrap();
        let local = candidates
            .iter()
            .copied()
            .find(|candidate| candidate.ip() == IpAddr::V4(ip))
            .expect("bound non-loopback interface candidate is gathered");
        let Some(stale_port) = local.port().checked_sub(16) else {
            continue;
        };
        let stale = SocketAddr::new(IpAddr::V4(ip), stale_port);
        if let Ok(blackhole) = UdpSocket::bind(stale).await {
            return (attempt, local, blackhole);
        }
    }
}

fn non_loopback_ipv4() -> Option<Ipv4Addr> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find_map(|interface| match interface.ip() {
            IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() => {
                Some(ip)
            }
            _ => None,
        })
}

#[tokio::test]
async fn stun_mapping_observations_preserve_destination_order_on_one_socket() {
    let server_a = reserve_loopback_udp_addr().await;
    let server_b = reserve_loopback_udp_addr().await;
    let (shutdown_a_tx, shutdown_a_rx) = watch::channel(false);
    let (shutdown_b_tx, shutdown_b_rx) = watch::channel(false);
    let server_a_task = tokio::spawn(serve_stun(server_a, shutdown_a_rx));
    let server_b_task = tokio::spawn(serve_stun(server_b, shutdown_b_rx));

    let mut attempt = UdpAttempt::bind(StunConfig {
        servers: Vec::new(),
        udp_bind_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        probe_timeout_millis: 2_000,
    })
    .await
    .unwrap();
    let (local_candidates, observations) = timeout(
        Duration::from_secs(2),
        attempt.gather_observations(&[server_a, server_b, server_a]),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(observations.len(), 3);
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.destination)
            .collect::<Vec<_>>(),
        [server_a, server_b, server_a]
    );
    let local_socket = observations[0].local_socket;
    assert_eq!(local_socket.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(
        local_candidates
            .iter()
            .any(|candidate| { candidate.address == local_socket && candidate.prefix_len == 8 })
    );
    assert!(
        observations
            .iter()
            .all(|observation| observation.local_socket == local_socket)
    );
    for observation in &observations {
        assert_eq!(observation.outcome.as_ref().unwrap(), &local_socket);
        assert!(observation.rtt < Duration::from_secs(1));
    }

    shutdown_a_tx.send(true).unwrap();
    shutdown_b_tx.send(true).unwrap();
    server_a_task.await.unwrap().unwrap();
    server_b_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn simulated_edm_filter_fallback_reaches_direct_quic_on_non_loopback() {
    let Some(interface_ip) = non_loopback_ipv4() else {
        eprintln!("skipped: test host has no non-loopback IPv4 interface");
        return;
    };
    let (mut client_attempt, client_socket, client_blackhole) =
        bind_attempt_with_stale_mapping(interface_ip).await;
    let (mut target_attempt, target_socket, target_blackhole) =
        bind_attempt_with_stale_mapping(interface_ip).await;
    let (stun_a, shutdown_a_tx, stun_a_task) = start_simulated_stun_server(interface_ip, 0).await;
    let (stun_b, shutdown_b_tx, stun_b_task) = start_simulated_stun_server(interface_ip, -16).await;
    let destinations = [stun_a, stun_b, stun_a];
    let (client_observations, target_observations) = tokio::join!(
        client_attempt.gather_observations(&destinations),
        target_attempt.gather_observations(&destinations),
    );
    let (client_candidates, client_mappings) = client_observations.unwrap();
    let (target_candidates, target_mappings) = target_observations.unwrap();
    let client_actual = client_candidates
        .iter()
        .find(|candidate| candidate.address.ip() == IpAddr::V4(interface_ip))
        .unwrap()
        .address;
    let target_actual = target_candidates
        .iter()
        .find(|candidate| candidate.address.ip() == IpAddr::V4(interface_ip))
        .unwrap()
        .address;
    assert_eq!(client_actual, client_socket);
    assert_eq!(target_actual, target_socket);
    for (mappings, actual, blackhole) in [
        (&client_mappings, client_actual, &client_blackhole),
        (&target_mappings, target_actual, &target_blackhole),
    ] {
        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[0].destination, stun_a);
        assert_eq!(mappings[1].destination, stun_b);
        assert_eq!(mappings[2].destination, stun_a);
        assert!(
            mappings
                .iter()
                .all(|mapping| mapping.local_socket == actual)
        );
        assert_eq!(mappings[0].outcome.as_ref().unwrap(), &actual);
        assert_eq!(
            mappings[1].outcome.as_ref().unwrap(),
            &blackhole.local_addr().unwrap()
        );
        assert_eq!(mappings[2].outcome.as_ref().unwrap(), &actual);
    }

    // The peer first probes a stale endpoint-dependent mapping, then the observed
    // host tuple. Unrelated UDP noise is discarded while authenticated probes arrive.
    let client_destinations = [*client_mappings[1].outcome.as_ref().unwrap(), client_actual];
    let target_destinations = [*target_mappings[1].outcome.as_ref().unwrap(), target_actual];
    let noise = UdpSocket::bind(SocketAddr::new(IpAddr::V4(interface_ip), 0))
        .await
        .unwrap();
    noise
        .send_to(b"unrelated UDP datagram", client_actual)
        .await
        .unwrap();
    noise
        .send_to(b"unrelated UDP datagram", target_actual)
        .await
        .unwrap();

    let session_id = Uuid::new_v4();
    let probe_token = [0x6a; 32];
    let (client_probe, target_probe) = tokio::join!(
        client_attempt.probe(
            session_id,
            probe_token,
            &target_destinations,
            Duration::from_secs(3),
        ),
        target_attempt.probe(
            session_id,
            probe_token,
            &client_destinations,
            Duration::from_secs(3),
        ),
    );
    assert_eq!(client_probe.unwrap().peer_addr, target_actual);
    assert_eq!(target_probe.unwrap().peer_addr, client_actual);

    let target_id = Uuid::new_v4();
    let identity = generate_target_certificate(target_id).unwrap();
    let certificate_der = rustls_pemfile::certs(&mut std::io::BufReader::new(
        identity.certificate_pem.as_bytes(),
    ))
    .next()
    .unwrap()
    .unwrap()
    .to_vec();
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
        stream.write_all(b"SSH-2.0-kmesh-edm-direct\r\n").await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
    });
    let mut client_stream = client_attempt
        .into_quic_client(
            target_id,
            target_actual,
            certificate_der,
            &identity.fingerprint,
            QuicConfig::default(),
        )
        .await
        .unwrap();
    client_stream
        .write_all(b"SSH-2.0-client-direct\r\n")
        .await
        .unwrap();
    client_stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"SSH-2.0-kmesh-edm-direct\r\n");
    assert_eq!(
        target_task.await.unwrap().unwrap(),
        b"SSH-2.0-client-direct\r\n"
    );

    shutdown_a_tx.send(true).unwrap();
    shutdown_b_tx.send(true).unwrap();
    stun_a_task.await.unwrap().unwrap();
    stun_b_task.await.unwrap().unwrap();
}
