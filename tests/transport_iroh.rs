use std::{net::SocketAddr, time::Duration};

use iroh::{
    Endpoint, RelayMode, SecretKey,
    endpoint::{NetReportConfig, PortmapperConfig, presets},
};
use kmesh::transport::{
    IROH_SSH_ALPN, IrohByteStream, IrohPathKind, RelayChoice, accept_peer, connect_peer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn loopback_endpoint(accept: bool) -> Endpoint {
    let alpns = if accept {
        vec![IROH_SSH_ALPN.to_vec()]
    } else {
        Vec::new()
    };
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(alpns)
        .relay_mode(RelayMode::Disabled)
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
        .clear_ip_transports()
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn iroh_stream_preserves_half_close_and_final_ssh_exit_status_bytes() {
    let target = loopback_endpoint(true).await;
    let client = loopback_endpoint(false).await;
    let target_addr = target.addr();
    let (mut sshd, mut agent_socket) = tokio::io::duplex(4096);
    let (mut ssh_client, mut client_socket) = tokio::io::duplex(4096);

    let target_task = tokio::spawn(async move {
        let connection = accept_peer(&target).await.unwrap();
        let mut stream = IrohByteStream::accept_bi(connection).await.unwrap();
        tokio::io::copy_bidirectional(&mut stream, &mut agent_socket)
            .await
            .unwrap();
        stream.finish_send_and_wait().await.unwrap();
    });
    let sshd_task = tokio::spawn(async move {
        let mut request = Vec::new();
        sshd.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"ssh request before client EOF");
        sshd.write_all(b"stdout final bytes\nSSH_EXIT_STATUS=7\n")
            .await
            .unwrap();
        sshd.shutdown().await.unwrap();
    });

    let relay_choice = RelayChoice::DirectOnly;
    let connection = connect_peer(&client, target_addr, &relay_choice)
        .await
        .unwrap();
    let mut stream = IrohByteStream::open_bi(connection).await.unwrap();
    assert_eq!(stream.selected_path().unwrap().kind, IrohPathKind::Direct);
    let client_task = tokio::spawn(async move {
        tokio::io::copy_bidirectional(&mut client_socket, &mut stream)
            .await
            .unwrap();
        stream.finish_send_and_wait().await.unwrap();
    });
    ssh_client
        .write_all(b"ssh request before client EOF")
        .await
        .unwrap();
    ssh_client.shutdown().await.unwrap();

    let response = tokio::time::timeout(Duration::from_secs(5), async {
        let mut response = Vec::new();
        ssh_client.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap();
    assert_eq!(response, b"stdout final bytes\nSSH_EXIT_STATUS=7\n");
    target_task.await.unwrap();
    sshd_task.await.unwrap();
    client_task.await.unwrap();
}
