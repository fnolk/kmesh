use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use kmesh::config::StunConfig;
use kmesh::transport::{UdpAttempt, serve_stun};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;

async fn reserve_loopback_udp_addr() -> SocketAddr {
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    socket.local_addr().unwrap()
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
    let observations = timeout(
        Duration::from_secs(2),
        attempt.observe_stun_mappings(&[server_a, server_b, server_a]),
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
