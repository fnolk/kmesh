use kmesh::transport::{BoxedIo, RelayByteStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::http::Request;

async fn relay_pair() -> (RelayByteStream, RelayByteStream) {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let server = tokio::spawn(async move {
        let io: BoxedIo = Box::new(server_io);
        RelayByteStream::from_ws(accept_async(io).await.unwrap())
    });
    let request = Request::builder()
        .method("GET")
        .uri("ws://kmesh.test/relay")
        .header("host", "kmesh.test")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    let io: BoxedIo = Box::new(client_io);
    let (client_ws, _) = client_async(request, io).await.unwrap();
    (RelayByteStream::from_ws(client_ws), server.await.unwrap())
}

#[tokio::test]
async fn relay_data_and_both_fin_frames_preserve_tcp_half_close() {
    let (mut client, mut target) = relay_pair().await;
    let request = (0..256 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    client.write_all(&request).await.unwrap();
    client.shutdown().await.unwrap();

    let mut request = Vec::new();
    target.read_to_end(&mut request).await.unwrap();
    assert_eq!(
        request,
        (0..256 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>()
    );

    target.write_all(b"target response").await.unwrap();
    target.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"target response");
}

#[tokio::test]
async fn relay_reset_and_abrupt_close_are_errors() {
    let (mut client, mut target) = relay_pair().await;
    client.reset(b"ssh session aborted").await.unwrap();
    let error = target.read_u8().await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);

    let (mut client, target) = relay_pair().await;
    drop(target);
    let error = client.read_u8().await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}
