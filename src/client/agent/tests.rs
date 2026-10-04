use super::{
    TunnelOffer, control::agent_session_error_code, route::endpoint_options, server_session_error,
    session::handle_dial_offer,
};
use crate::client::{ClientContext, api::Api, profile, proxy::read_ticket};
use crate::{
    protocol::{ControlMessage, RouteMode, TransportInfo},
    transport::{IrohByteStream, RelayChoice, TransportError, accept_peer, connect_peer},
};
use anyhow::Result;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use std::{io, time::Duration};
use tokio::time::Instant;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use uuid::Uuid;

#[test]
fn per_session_error_classification_keeps_auth_and_protocol_failures_terminal() {
    assert_eq!(
        agent_session_error_code(&anyhow::Error::new(TransportError::Tls(
            "QAD certificate rejected".to_owned()
        ))),
        "authentication"
    );
    assert_eq!(
        agent_session_error_code(&anyhow::Error::new(TransportError::ProtocolViolation(
            "wrong punch SID".to_owned()
        ))),
        "authentication"
    );
    assert_eq!(
        agent_session_error_code(&anyhow::Error::new(TransportError::Configuration(
            "invalid private relay".to_owned()
        ))),
        "configuration"
    );
    assert_eq!(
        agent_session_error_code(&anyhow::Error::new(TransportError::Network(
            io::Error::from(io::ErrorKind::NetworkUnreachable)
        ))),
        "network"
    );
}

#[test]
fn server_network_errors_remain_retryable_route_failures() {
    assert_eq!(
        agent_session_error_code(&server_session_error(
            "network",
            "direct path timed out".to_owned(),
        )),
        "network"
    );
    assert_eq!(
        agent_session_error_code(&server_session_error(
            "configuration",
            "private relay is unavailable".to_owned(),
        )),
        "configuration"
    );
    assert_eq!(
        agent_session_error_code(&server_session_error(
            "unexpected_code",
            "invalid route message".to_owned(),
        )),
        "authentication"
    );
}

async fn context(server_url: &str) -> ClientContext {
    let config = crate::config::Config {
        server_url: server_url.to_owned(),
        ..crate::config::Config::default()
    };
    let api = Api::new(&config).await.expect("build test API client");
    let profiles =
        profile::ProfileStore::new(&config.data_dir, &config.server_url, &config.profile);
    ClientContext {
        config,
        config_path: None,
        api,
        profiles,
    }
}

async fn local_endpoints() -> (Endpoint, Endpoint) {
    let client = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![crate::transport::IROH_SSH_ALPN.to_vec()])
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .expect("bind local accepting client endpoint");
    let target = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .expect("bind local dialing target endpoint");
    (client, target)
}

fn offer(client: &Endpoint) -> TunnelOffer {
    TunnelOffer {
        session_id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        ticket: "signed-test-ticket".to_owned(),
        client_endpoint_id: client.id().to_string(),
        client_endpoint_addr: client.addr(),
        ticket_public_key_pem: String::new(),
        route_mode: RouteMode::PublicDirect,
    }
}

async fn await_offer(task: tokio::task::JoinHandle<Result<()>>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("agent dial did not finish promptly")
        .expect("agent dial task panicked")
}

#[tokio::test]
async fn direct_route_uses_no_relay_and_private_relay_requires_configuration() {
    let context = context("https://kmesh.test:9443").await;
    let info = TransportInfo {
        private_relay_url: None,
        qad_port: 3478,
    };

    let public = endpoint_options(&context, &info, RouteMode::PublicDirect, None)
        .expect("public direct mode does not require a private relay");
    assert_eq!(public.relay_choice, RelayChoice::DirectOnly);
    assert!(endpoint_options(&context, &info, RouteMode::PrivateRelay, None).is_err());
}

#[tokio::test]
async fn private_relay_must_match_the_authenticated_service_origin() {
    let context = context("https://kmesh.test:9443").await;
    let info = TransportInfo {
        private_relay_url: Some("https://kmesh.test:9443".to_owned()),
        qad_port: 3478,
    };
    let options = endpoint_options(&context, &info, RouteMode::PrivateRelay, None)
        .expect("server private relay matches the control service");
    assert_eq!(
        options.relay_choice,
        RelayChoice::Private {
            url: reqwest::Url::parse("https://kmesh.test:9443").unwrap(),
            quic_port: 3478,
        }
    );

    let malicious = TransportInfo {
        private_relay_url: Some("https://untrusted.example".to_owned()),
        qad_port: 3478,
    };
    assert!(endpoint_options(&context, &malicious, RouteMode::PrivateRelay, None).is_err());
}

#[tokio::test]
async fn target_dials_the_client_and_reports_only_after_ticket_write() {
    let context = context("https://kmesh.test:9443").await;
    let (client, target) = local_endpoints().await;
    let offer = offer(&client);
    let session_id = offer.session_id;
    let client_endpoint_id = client.id().to_string();
    let target_data_endpoint_id = target.id().to_string();
    let client_task = tokio::spawn(async move {
        let connection = accept_peer(&client)
            .await
            .expect("accept target connection");
        let mut stream = IrohByteStream::accept_bi(connection)
            .await
            .expect("accept target ticket stream");
        read_ticket(&mut stream).await.expect("read target ticket")
    });
    let (control_tx, control_rx) = mpsc::channel(1);
    let (outbound, mut outbound_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        handle_dial_offer(
            &context,
            offer,
            &target,
            RelayChoice::DirectOnly,
            Instant::now() + Duration::from_secs(5),
            control_rx,
            outbound,
        )
        .await
    });

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), outbound_rx.recv())
            .await
            .expect("target did not report selected path")
        .expect("target control channel closed"),
        ControlMessage::PathReady {
            session_id: received,
            route_mode: RouteMode::PublicDirect,
            path: crate::protocol::SelectedPath::Direct { .. },
        } if received == session_id
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), outbound_rx.recv())
            .await
            .expect("target did not report Iroh readiness")
        .expect("target control channel closed"),
        ControlMessage::IrohReady { session_id: received, client_endpoint_id: reported_id, target_data_endpoint_id: target_data, route_mode: RouteMode::PublicDirect }
            if received == session_id && reported_id == client_endpoint_id && target_data == target_data_endpoint_id
    ));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client_task)
            .await
            .expect("client did not receive the ticket")
            .expect("client accept task panicked"),
        "signed-test-ticket"
    );
    control_tx
        .send(ControlMessage::Close {
            session_id,
            reason: "test complete".to_owned(),
        })
        .await
        .expect("cancel pending SSH activation");
    assert!(await_offer(task).await.is_ok());
}

#[tokio::test]
async fn close_cancels_target_dial_before_client_accepts() {
    let context = context("https://kmesh.test:9443").await;
    let (client, target) = local_endpoints().await;
    let offer = offer(&client);
    let session_id = offer.session_id;
    let (control_tx, control_rx) = mpsc::channel(1);
    let (outbound, _outbound_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        handle_dial_offer(
            &context,
            offer,
            &target,
            RelayChoice::DirectOnly,
            Instant::now() + Duration::from_secs(5),
            control_rx,
            outbound,
        )
        .await
    });

    tokio::task::yield_now().await;
    control_tx
        .send(ControlMessage::Close {
            session_id,
            reason: "cancelled".to_owned(),
        })
        .await
        .expect("send session close");
    assert!(await_offer(task).await.is_ok());
}

#[tokio::test]
async fn control_disconnect_cancels_target_dial() {
    let context = context("https://kmesh.test:9443").await;
    let (client, target) = local_endpoints().await;
    let offer = offer(&client);
    let (control_tx, control_rx) = mpsc::channel(1);
    let (outbound, _outbound_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        handle_dial_offer(
            &context,
            offer,
            &target,
            RelayChoice::DirectOnly,
            Instant::now() + Duration::from_secs(5),
            control_rx,
            outbound,
        )
        .await
    });
    drop(control_tx);
    assert!(await_offer(task).await.is_ok());
}

#[tokio::test]
async fn closing_a_second_session_endpoint_keeps_the_first_ssh_stream_alive() {
    let (client_one, target_one) = local_endpoints().await;
    let (_client_two, target_two) = local_endpoints().await;
    let session_one_endpoint_id = target_one.id();
    let session_two_endpoint_id = target_two.id();
    assert_ne!(session_one_endpoint_id, session_two_endpoint_id);
    assert_ne!(target_one.bound_sockets(), target_two.bound_sockets());

    let client_one_addr = client_one.addr();
    let accept_endpoint = client_one.clone();
    let accept_task = tokio::spawn(async move { accept_peer(&accept_endpoint).await });
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        connect_peer(&target_one, client_one_addr, &RelayChoice::DirectOnly),
    )
    .await
    .expect("first session connection timed out")
    .expect("first session target connects");
    let incoming = tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .expect("first session client did not accept")
        .expect("first session accept task panicked")
        .expect("first session client accepts");
    let mut target_stream =
        tokio::time::timeout(Duration::from_secs(5), IrohByteStream::open_bi(connection))
            .await
            .expect("first session stream open timed out")
            .expect("open first session stream");
    tokio::time::timeout(
        Duration::from_secs(5),
        target_stream.write_all(b"stream ready"),
    )
    .await
    .expect("first session stream warmup write timed out")
    .expect("write first session stream warmup");
    tokio::time::timeout(Duration::from_secs(5), target_stream.flush())
        .await
        .expect("first session stream warmup flush timed out")
        .expect("flush first session stream warmup");
    let mut client_stream =
        tokio::time::timeout(Duration::from_secs(5), IrohByteStream::accept_bi(incoming))
            .await
            .expect("first session stream accept timed out")
            .expect("accept first session stream");
    let mut warmup_received = [0; 12];
    tokio::time::timeout(
        Duration::from_secs(5),
        client_stream.read_exact(&mut warmup_received),
    )
    .await
    .expect("first session warmup read timed out")
    .expect("read first session stream warmup");
    assert_eq!(&warmup_received, b"stream ready");

    tokio::time::timeout(Duration::from_secs(5), target_two.close())
        .await
        .expect("closing the second session endpoint timed out");
    let active_payload = b"active session survives";
    tokio::time::timeout(
        Duration::from_secs(5),
        target_stream.write_all(active_payload),
    )
    .await
    .expect("write on first session after closing the second endpoint timed out")
    .expect("write on first session after closing the second endpoint");
    let mut received = vec![0; active_payload.len()];
    tokio::time::timeout(
        Duration::from_secs(5),
        client_stream.read_exact(&mut received),
    )
    .await
    .expect("first session read timed out")
    .expect("read first session payload");
    assert_eq!(received, active_payload);
}
