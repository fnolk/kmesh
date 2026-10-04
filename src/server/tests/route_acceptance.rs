use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    process::{Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use iroh::endpoint::VarInt;
use iroh::{EndpointAddr, SecretKey};
use iroh_relay::server::{Access, AccessControl, ClientRequest, DynAccessControl};
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command as TokioCommand,
    sync::oneshot,
    task::JoinHandle,
    time::{Instant, timeout},
};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    client::{self, Cli, Command as ClientCommand},
    config::{Config, TlsConfig},
    identity,
    protocol::{
        ControlMessage, DiscoveryResult, LoginTokens, NativePlan, PasswordLoginRequest, RouteMode,
        SelectedPath, TunnelTicketClaims,
    },
    transport::{
        IrohByteStream, IrohEndpointOptions, IrohPathKind, QadReflector, RelayChoice, connect_peer,
        create_endpoint, observe_ipv4_mappings, wait_endpoint_ready, wait_for_selected_path,
    },
};

use super::{
    Fixture, connect_control_ws, create_enrolled_target, fixture, grant_target, send_control,
};

const LOCAL_PRIVATE_QAD: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3478);
const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "initial-admin-password";
const SSH_BANNER: &[u8] = b"SSH-2.0-kmesh-route-fixture\r\n";
const SSH_REQUEST: &[u8] = b"kmesh fixture command\n";
const SSH_RESPONSE: &[u8] = b"fixture command output\n";

#[derive(Clone)]
struct RelayAccessPolicy {
    state: super::super::ServerState,
    denied_client_ids: Arc<Mutex<HashSet<String>>>,
    denial_count: Arc<AtomicU64>,
}

impl AccessControl for RelayAccessPolicy {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let endpoint_id = request.endpoint_id().to_string();
        let denied = self
            .denied_client_ids
            .lock()
            .expect("relay deny set lock poisoned")
            .contains(&endpoint_id);
        if denied {
            self.denial_count.fetch_add(1, Ordering::Relaxed);
            return Access::Deny {
                reason: Some(
                    "route acceptance fixture rejected private relay registration".to_owned(),
                ),
            };
        }
        AccessControl::on_connect(&self.state, request).await
    }
}

impl std::fmt::Debug for RelayAccessPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayAccessPolicy")
            .finish_non_exhaustive()
    }
}

struct LocalServer {
    fixture: Fixture,
    issuer: String,
    tls: TlsConfig,
    access: RelayAccessPolicy,
    stop_server: Option<oneshot::Sender<()>>,
    server_task: JoinHandle<Result<()>>,
}

impl LocalServer {
    async fn start() -> Result<Self> {
        Self::start_at(LOCAL_PRIVATE_QAD).await
    }

    async fn start_at(qad_bind: SocketAddr) -> Result<Self> {
        let port_probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let https_port = port_probe.local_addr()?.port();
        drop(port_probe);
        let issuer = format!("https://localhost:{https_port}");
        let fixture = fixture(&issuer).await;
        let cert = generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let cert_path = fixture.data_dir.join("route-relay-cert.pem");
        let key_path = fixture.data_dir.join("route-relay-key.pem");
        fs::write(&cert_path, cert.cert.pem())?;
        fs::write(&key_path, cert.signing_key.serialize_pem())?;
        let tls = TlsConfig {
            ca_certificates: vec![cert_path.clone()],
            ..TlsConfig::default()
        };
        let _http_client = crate::transport::http_client(&tls)?;
        let access = RelayAccessPolicy {
            state: fixture.state.clone(),
            denied_client_ids: Arc::new(Mutex::new(HashSet::new())),
            denial_count: Arc::new(AtomicU64::new(0)),
        };
        let relay_access: Arc<dyn DynAccessControl> = Arc::new(access.clone());
        let server = super::super::iroh::listen_and_serve(
            super::super::router(fixture.state.clone()),
            Some(relay_access),
            SocketAddr::from(([127, 0, 0, 1], https_port)),
            qad_bind,
            &cert_path,
            &key_path,
        )
        .await
        .context("start loopback HTTPS, private relay and QAD fixture")?;
        fixture.state.inner.transport_info.write().await.qad_port = server.qad_addr().port();
        let (stop_server, stop_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let _ = stop_rx.await;
            server.shutdown().await
        });
        Ok(Self {
            fixture,
            issuer,
            tls,
            access,
            stop_server: Some(stop_server),
            server_task,
        })
    }

    fn state(&self) -> &super::super::ServerState {
        &self.fixture.state
    }

    fn client_config(&self) -> Result<PathBuf> {
        let data_dir = self.fixture.data_dir.join("route-client-state");
        let config = Config {
            profile: "route-acceptance".to_owned(),
            server_url: self.issuer.clone(),
            data_dir,
            tls: self.tls.clone(),
            ..Config::default()
        };
        let path = self.fixture.data_dir.join("route-client-config.toml");
        fs::write(&path, toml::to_string(&config)?)?;
        Ok(path)
    }

    async fn shutdown(mut self) -> Result<()> {
        if let Some(stop_server) = self.stop_server.take() {
            let _ = stop_server.send(());
        }
        timeout(Duration::from_secs(5), &mut self.server_task)
            .await
            .context("loopback server shutdown timed out")??
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        if let Some(stop_server) = self.stop_server.take() {
            let _ = stop_server.send(());
        }
        self.server_task.abort();
    }
}

#[derive(Clone, Copy, Debug)]
struct DropStats {
    datagrams: u64,
    bytes: u64,
}

struct UdpDropper {
    addr: SocketAddrV4,
    datagrams: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    receiver: Option<JoinHandle<()>>,
}

impl UdpDropper {
    async fn bind() -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = match socket.local_addr()? {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => bail!("loopback UDP dropper unexpectedly bound IPv6"),
        };
        let datagrams = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let receiver_datagrams = datagrams.clone();
        let receiver_bytes = bytes.clone();
        let receiver = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((len, _)) = socket.recv_from(&mut buffer).await {
                receiver_datagrams.fetch_add(1, Ordering::Relaxed);
                receiver_bytes.fetch_add(len as u64, Ordering::Relaxed);
            }
        });
        Ok(Self {
            addr,
            datagrams,
            bytes,
            receiver: Some(receiver),
        })
    }

    async fn stop(mut self) -> DropStats {
        if let Some(receiver) = self.receiver.take() {
            receiver.abort();
            let _ = receiver.await;
        }
        DropStats {
            datagrams: self.datagrams.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

impl Drop for UdpDropper {
    fn drop(&mut self) {
        if let Some(receiver) = self.receiver.take() {
            receiver.abort();
        }
    }
}

#[derive(Debug)]
struct DirectAttemptEvidence {
    session_id: Uuid,
    route_mode: RouteMode,
    target_qad_drop: DropStats,
    native_udp_drop: DropStats,
    native_dial_failure: String,
}

#[derive(Debug)]
struct RelayStreamEvidence {
    session_id: Uuid,
    selected_url: String,
    selected_remote_address: String,
    tx_delta: u64,
    rx_delta: u64,
}

#[derive(Debug, Default)]
struct TargetEvidence {
    direct_attempts: Vec<DirectAttemptEvidence>,
    relay_session_id: Option<Uuid>,
    relay_refusal_stage: Option<String>,
    relay_stream: Option<RelayStreamEvidence>,
}

async fn probe_qad_blackhole() -> Result<(String, DropStats)> {
    // Use the real QAD client against a local UDP listener that records packets and never replies.
    let dropper = UdpDropper::bind().await?;
    let source = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let reflector = [QadReflector {
        addr: dropper.addr,
        server_name: "localhost".to_owned(),
    }];
    let deadline = Instant::now() + Duration::from_millis(400);
    let probe = observe_ipv4_mappings(source, tls, &reflector, deadline, deadline).await;
    let error = match probe {
        Ok(_) => bail!("controlled UDP dropper unexpectedly completed a QAD handshake"),
        Err(error) => error,
    };
    let stats = dropper.stop().await;
    ensure!(stats.datagrams > 0, "QAD blackhole received no UDP packets");
    Ok((
        format!(
            "controlled QAD UDP blackhole observed {} datagrams/{} bytes: {error:#}",
            stats.datagrams, stats.bytes
        ),
        stats,
    ))
}

async fn receive_agent_control(
    websocket: &mut crate::transport::WsStream,
) -> Result<ControlMessage> {
    loop {
        let Some(message) = websocket.next().await else {
            bail!("agent control WebSocket ended");
        };
        match message? {
            Message::Text(text) => return Ok(serde_json::from_str(text.as_str())?),
            Message::Binary(bytes) => return Ok(serde_json::from_slice(&bytes)?),
            Message::Ping(bytes) => websocket.send(Message::Pong(bytes)).await?,
            Message::Pong(_) => {}
            Message::Close(_) | Message::Frame(_) => bail!("agent control WebSocket closed"),
        }
    }
}

async fn next_agent_control(
    websocket: &mut crate::transport::WsStream,
    budget: Duration,
) -> Result<ControlMessage> {
    timeout(budget, receive_agent_control(websocket))
        .await
        .context("agent control message deadline elapsed")?
}

async fn wait_target_online(state: &super::super::ServerState, target_id: Uuid) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            if state
                .inner
                .online_agents
                .read()
                .await
                .contains_key(&target_id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("agent did not register as online")
}

async fn drive_target(
    server: &LocalServer,
    target_id: Uuid,
    agent_token: String,
    device_key: SecretKey,
    deny_private_relay: bool,
    ssh_addr: Option<SocketAddr>,
) -> Result<TargetEvidence> {
    let mut agent_control =
        connect_control_ws(&server.issuer, "agent/control", &agent_token, &server.tls).await;
    wait_target_online(server.state(), target_id).await?;

    let mut evidence = TargetEvidence::default();
    loop {
        let message = next_agent_control(&mut agent_control, Duration::from_secs(65)).await?;
        let ControlMessage::Prepare {
            session_id,
            route_mode,
            client_endpoint_id,
            expires_at,
        } = message
        else {
            bail!("target fixture expected Prepare, received {message:?}");
        };
        if deny_private_relay && route_mode == RouteMode::PrivateRelay {
            server
                .access
                .denied_client_ids
                .lock()
                .expect("relay deny set lock poisoned")
                .insert(client_endpoint_id.clone());
        }
        let client_data_id = client_endpoint_id.parse::<iroh::EndpointId>()?;
        let target_data_key = SecretKey::generate();
        let target_data_id = target_data_key.public();
        let signature = device_key
            .sign(&identity::agent_session_identity_payload(
                session_id,
                target_id,
                route_mode,
                &target_data_id,
                expires_at,
            ))
            .to_bytes()
            .to_vec();
        send_control(
            &mut agent_control,
            &ControlMessage::AgentIdentity {
                session_id,
                route_mode,
                target_data_endpoint_id: target_data_id.to_string(),
                signature,
            },
        )
        .await;
        ensure!(
            matches!(
                next_agent_control(&mut agent_control, Duration::from_secs(10)).await?,
                ControlMessage::IdentityAccepted { session_id: received, route_mode: mode }
                    if received == session_id && mode == route_mode
            ),
            "server did not accept the signed per-session target identity"
        );

        match route_mode {
            RouteMode::PrivateDirect | RouteMode::PublicDirect => {
                let (reason, target_qad_drop) = probe_qad_blackhole().await?;
                send_control(
                    &mut agent_control,
                    &ControlMessage::CandidatesReady {
                        session_id,
                        route_mode,
                        discovery: DiscoveryResult::Unavailable { reason },
                    },
                )
                .await;
                ensure!(
                    matches!(
                        next_agent_control(&mut agent_control, Duration::from_secs(10)).await?,
                        ControlMessage::ContinueNative {
                            session_id: received,
                            route_mode: mode,
                            plan: NativePlan::Standard,
                        } if received == session_id && mode == route_mode
                    ),
                    "server did not continue to native direct setup after the measured QAD timeout"
                );

                let native_dropper = UdpDropper::bind().await?;
                let relay_choice = RelayChoice::DirectOnly;
                let endpoint = create_endpoint(
                    target_data_key,
                    false,
                    IrohEndpointOptions {
                        relay_choice: relay_choice.clone(),
                        tls: server.tls.clone(),
                        handoff: None,
                    },
                )
                .await?;
                // This test peer advertises a controlled NAT entrance. Iroh attempts the real
                // QUIC connection against it; the fixture records and drops each received UDP
                // datagram, so no selected direct path is reported or simulated.
                let target_advertised_addr = EndpointAddr::new(endpoint.id())
                    .with_ip_addr(SocketAddr::V4(native_dropper.addr));
                send_control(
                    &mut agent_control,
                    &ControlMessage::AgentReady {
                        session_id,
                        route_mode,
                        endpoint_addr: target_advertised_addr,
                    },
                )
                .await;
                let ControlMessage::DialOffer {
                    session_id: offered_session,
                    target_id: offered_target,
                    ticket,
                    client_endpoint_id: offered_client,
                    ticket_public_key_pem,
                    route_mode: offered_mode,
                    ..
                } = next_agent_control(&mut agent_control, Duration::from_secs(10)).await?
                else {
                    bail!("server did not send the direct route DialOffer");
                };
                ensure!(
                    offered_session == session_id
                        && offered_target == target_id
                        && offered_client == client_endpoint_id
                        && offered_mode == route_mode,
                    "direct DialOffer identity differs from its pending session"
                );
                let claims: TunnelTicketClaims = identity::decode_tunnel_ticket(
                    &ticket,
                    &ticket_public_key_pem,
                    &server.issuer,
                )?;
                ensure!(
                    claims.session_id == session_id
                        && claims.client_endpoint_id == client_endpoint_id
                        && claims.target_endpoint_id == target_data_id.to_string()
                        && claims.route_mode == route_mode,
                    "direct route ticket claims do not match the signed session"
                );

                let blackhole_peer = EndpointAddr::new(client_data_id)
                    .with_ip_addr(SocketAddr::V4(native_dropper.addr));
                let dial_endpoint = endpoint.clone();
                let dial_choice = relay_choice.clone();
                let dial = tokio::spawn(async move {
                    timeout(
                        Duration::from_secs(8),
                        connect_peer(&dial_endpoint, blackhole_peer, &dial_choice),
                    )
                    .await
                });
                let close_message =
                    match next_agent_control(&mut agent_control, Duration::from_secs(40)).await? {
                        ControlMessage::Close {
                            session_id: closed,
                            reason,
                        } if closed == session_id => reason,
                        other => bail!("unexpected direct-session control message: {other:?}"),
                    };
                let dial_result = timeout(Duration::from_secs(2), dial)
                    .await
                    .context("Noq direct dial task did not finish its bounded timeout")?
                    .context("Noq direct dial task failed")?;
                let native_dial_failure = match dial_result {
                    Err(_) => "controlled Noq direct dial deadline elapsed".to_owned(),
                    Ok(Err(error)) if error.is_network_failure() => error.to_string(),
                    Ok(Err(error)) => {
                        bail!("Noq direct dial failed outside the network class: {error}")
                    }
                    Ok(Ok(connection)) => {
                        connection.close(VarInt::from_u32(0), b"unexpected direct success");
                        bail!("controlled blackhole unexpectedly completed a QUIC connection")
                    }
                };
                endpoint.close().await;
                let native_udp_drop = native_dropper.stop().await;
                ensure!(
                    native_udp_drop.datagrams > 0,
                    "direct Iroh dial produced no UDP packets at the controlled dropper"
                );
                ensure!(
                    !close_message.is_empty(),
                    "server closed a failed direct attempt without its phase reason"
                );
                evidence.direct_attempts.push(DirectAttemptEvidence {
                    session_id,
                    route_mode,
                    target_qad_drop,
                    native_udp_drop,
                    native_dial_failure,
                });
            }
            RouteMode::PrivateRelay => {
                evidence.relay_session_id = Some(session_id);
                ensure!(
                    matches!(
                        next_agent_control(&mut agent_control, Duration::from_secs(10)).await?,
                        ControlMessage::ContinueNative {
                            session_id: received,
                            route_mode: RouteMode::PrivateRelay,
                            plan: NativePlan::Standard,
                        } if received == session_id
                    ),
                    "server did not select the private relay plan"
                );
                let relay_choice = RelayChoice::Private {
                    url: server.issuer.parse()?,
                    quic_port: 3478,
                };
                let expected_relay_url = reqwest::Url::parse(&server.issuer)?.to_string();
                let endpoint = create_endpoint(
                    target_data_key,
                    false,
                    IrohEndpointOptions {
                        relay_choice: relay_choice.clone(),
                        tls: server.tls.clone(),
                        handoff: None,
                    },
                )
                .await?;
                let endpoint_ready = wait_endpoint_ready(
                    &endpoint,
                    &relay_choice,
                    Instant::now() + Duration::from_secs(10),
                )
                .await;
                if let Err(error) = endpoint_ready {
                    if deny_private_relay
                        && error.is_auth_failure()
                        && server.access.denial_count.load(Ordering::Relaxed) > 0
                    {
                        ensure!(
                            server
                                .access
                                .denied_client_ids
                                .lock()
                                .expect("relay deny set lock poisoned")
                                .contains(&client_endpoint_id),
                            "relay refusal was not for this session's client EndpointId"
                        );
                        ensure!(
                            matches!(
                                next_agent_control(
                                    &mut agent_control,
                                    Duration::from_secs(25)
                                )
                                .await?,
                                ControlMessage::Close { session_id: closed, .. }
                                    if closed == session_id
                            ),
                            "client did not close the pending private relay session after denial"
                        );
                        wait_for_tunnel_status(server.state(), &[session_id], "closed").await?;
                        evidence.relay_refusal_stage = Some(format!(
                            "target relay readiness ended after client EndpointId denial: {error}"
                        ));
                        endpoint.close().await;
                        return Ok(evidence);
                    }
                    return Err(anyhow::Error::new(error));
                }
                send_control(
                    &mut agent_control,
                    &ControlMessage::AgentReady {
                        session_id,
                        route_mode,
                        endpoint_addr: endpoint.addr(),
                    },
                )
                .await;

                if deny_private_relay {
                    ensure!(
                        matches!(
                            next_agent_control(&mut agent_control, Duration::from_secs(25)).await?,
                            ControlMessage::Close { session_id: closed, .. }
                                if closed == session_id
                        ),
                        "client did not close the private relay attempt after the relay refused its endpoint"
                    );
                    ensure!(
                        server.access.denial_count.load(Ordering::Relaxed) > 0,
                        "private relay access policy did not reject a real client EndpointId"
                    );
                    evidence.relay_refusal_stage = Some(
                        "client private relay registration denied before target dial".to_owned(),
                    );
                    endpoint.close().await;
                    return Ok(evidence);
                }

                let ControlMessage::DialOffer {
                    session_id: offered_session,
                    target_id: offered_target,
                    ticket,
                    client_endpoint_id: offered_client,
                    client_endpoint_addr,
                    ticket_public_key_pem,
                    route_mode: offered_mode,
                } = next_agent_control(&mut agent_control, Duration::from_secs(15)).await?
                else {
                    bail!("server did not send the private relay DialOffer");
                };
                ensure!(
                    offered_session == session_id
                        && offered_target == target_id
                        && offered_client == client_endpoint_id
                        && offered_mode == RouteMode::PrivateRelay,
                    "private relay DialOffer identity differs from its pending session"
                );
                ensure!(
                    client_endpoint_addr.relay_urls().count() == 1
                        && client_endpoint_addr.ip_addrs().next().is_none(),
                    "private relay DialOffer contains a direct endpoint candidate"
                );
                let claims: TunnelTicketClaims = identity::decode_tunnel_ticket(
                    &ticket,
                    &ticket_public_key_pem,
                    &server.issuer,
                )?;
                ensure!(
                    claims.session_id == session_id
                        && claims.client_endpoint_id == client_endpoint_id
                        && claims.target_endpoint_id == target_data_id.to_string()
                        && claims.route_mode == RouteMode::PrivateRelay,
                    "private relay ticket claims do not match the signed session"
                );

                let connection = timeout(
                    Duration::from_secs(15),
                    connect_peer(&endpoint, client_endpoint_addr, &relay_choice),
                )
                .await
                .context("target QUIC connect via private relay timed out")??;
                let selected = wait_for_selected_path(
                    &connection,
                    RouteMode::PrivateRelay,
                    Instant::now() + Duration::from_secs(10),
                )
                .await?;
                let SelectedPath::PrivateRelay { url } = &selected else {
                    bail!("target selected a direct path in private relay mode: {selected:?}");
                };
                ensure!(
                    url == &expected_relay_url,
                    "target selected an unexpected relay URL"
                );
                let selected_relay_url = url.clone();
                send_control(
                    &mut agent_control,
                    &ControlMessage::PathReady {
                        session_id,
                        route_mode: RouteMode::PrivateRelay,
                        path: selected,
                    },
                )
                .await;

                let mut stream = IrohByteStream::open_bi(connection.clone()).await?;
                stream.write_u32(ticket.len() as u32).await?;
                stream.write_all(ticket.as_bytes()).await?;
                send_control(
                    &mut agent_control,
                    &ControlMessage::IrohReady {
                        session_id,
                        client_endpoint_id,
                        target_data_endpoint_id: target_data_id.to_string(),
                        route_mode: RouteMode::PrivateRelay,
                    },
                )
                .await;
                ensure!(
                    matches!(
                        next_agent_control(&mut agent_control, Duration::from_secs(10)).await?,
                        ControlMessage::Activated { session_id: active }
                            if active == session_id
                    ),
                    "server did not activate the private relay session"
                );

                let ssh_addr = ssh_addr.context("successful relay route has no SSH fixture")?;
                let mut ssh = TcpStream::connect(ssh_addr).await?;
                let selected_path_before = stream
                    .selected_path()
                    .context("private relay stream has no selected Iroh path")?;
                ensure!(
                    selected_path_before.kind == IrohPathKind::Relay
                        && selected_path_before.remote_address.contains(&server.issuer),
                    "pre-data Iroh path was not the configured private relay"
                );
                let path_before = stream.path_stats();
                let (target_to_client, client_to_target) = timeout(
                    Duration::from_secs(20),
                    tokio::io::copy_bidirectional(&mut ssh, &mut stream),
                )
                .await
                .context("SSH fixture stream timed out over private relay")??;
                stream.finish_send_and_wait().await?;
                let path_after = stream.path_stats();
                let selected_path_after = stream
                    .selected_path()
                    .context("private relay stream lost its selected Iroh path")?;
                ensure!(
                    selected_path_after.kind == IrohPathKind::Relay
                        && selected_path_after.remote_address.contains(&server.issuer),
                    "post-data Iroh path was not the configured private relay"
                );
                let before = path_before
                    .iter()
                    .find(|path| path.selected && path.kind == IrohPathKind::Relay)
                    .context("selected relay path has no pre-data stats")?;
                let after = path_after
                    .iter()
                    .find(|path| path.selected && path.kind == IrohPathKind::Relay)
                    .context("selected relay path has no post-data stats")?;
                let tx_delta = after.udp_tx_bytes.saturating_sub(before.udp_tx_bytes);
                let rx_delta = after.udp_rx_bytes.saturating_sub(before.udp_rx_bytes);
                ensure!(
                    tx_delta > 0 && rx_delta > 0,
                    "private relay selected-path QUIC byte counters did not grow bidirectionally"
                );
                connection.close(VarInt::from_u32(0), b"route acceptance fixture complete");
                ensure!(
                    client_to_target as usize == SSH_REQUEST.len(),
                    "SSH request byte count differs from the client fixture input"
                );
                let _ = target_to_client;
                ensure!(
                    matches!(
                        next_agent_control(&mut agent_control, Duration::from_secs(15)).await?,
                        ControlMessage::Close { session_id: closed, .. }
                            if closed == session_id
                    ),
                    "client did not close the completed private relay session"
                );
                evidence.relay_stream = Some(RelayStreamEvidence {
                    session_id,
                    selected_url: selected_relay_url,
                    selected_remote_address: selected_path_after.remote_address,
                    tx_delta,
                    rx_delta,
                });
                return Ok(evidence);
            }
        }
    }
}

fn client_binary() -> Result<PathBuf> {
    let path = std::env::var_os("KMESH_ROUTE_ACCEPTANCE_KMESH_BIN").context(
        "set KMESH_ROUTE_ACCEPTANCE_KMESH_BIN to the kmesh binary built from this source ref",
    )?;
    let path = PathBuf::from(path);
    ensure!(
        path.is_absolute() && path.is_file(),
        "route acceptance kmesh binary is unavailable: {}",
        path.display()
    );
    Ok(path)
}

async fn run_client_cli(
    mode: &str,
    config_path: &Path,
    target_id: Option<Uuid>,
    stdin: &[u8],
    budget: Duration,
) -> Result<Output> {
    let mut command = TokioCommand::new(client_binary()?);
    command
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    match mode {
        "login" => {
            command.args([
                "login",
                "--method",
                "password",
                "--username",
                ADMIN_USERNAME,
                "--password-stdin",
            ]);
        }
        "proxy" => {
            command.arg("proxy").arg(
                target_id
                    .context("proxy CLI requires a target ID")?
                    .to_string(),
            );
        }
        other => bail!("unknown route acceptance CLI operation {other}"),
    }
    let mut child = command.spawn().context("spawn kmesh client CLI")?;
    if !stdin.is_empty() {
        child
            .stdin
            .take()
            .context("open client CLI child stdin")?
            .write_all(stdin)
            .await
            .context("write client CLI child stdin")?;
    } else {
        drop(child.stdin.take());
    }
    timeout(budget, child.wait_with_output())
        .await
        .context("client CLI child deadline elapsed")?
        .context("wait for client CLI child")
}

async fn login_client(config_path: &Path) -> Result<()> {
    let password = format!("{ADMIN_PASSWORD}\n");
    let output = run_client_cli(
        "login",
        config_path,
        None,
        password.as_bytes(),
        Duration::from_secs(15),
    )
    .await?;
    ensure!(
        output.status.success(),
        "client CLI password login failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn enroll_and_grant_target(server: &LocalServer) -> Result<(Uuid, String, SecretKey)> {
    let device_key = SecretKey::generate();
    let (target_id, agent_token) =
        create_enrolled_target(server.state(), "route-acceptance-target", &device_key).await;
    grant_target(server.state(), target_id).await;
    Ok((target_id, agent_token, device_key))
}

async fn start_ssh_fixture() -> Result<(SocketAddr, JoinHandle<Result<Vec<u8>>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        stream.write_all(SSH_BANNER).await?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        stream.write_all(SSH_RESPONSE).await?;
        stream.shutdown().await?;
        Ok(request)
    });
    Ok((addr, task))
}

async fn run_proxy(config_path: &Path, target_id: Uuid, stdin: &[u8]) -> Result<Output> {
    run_client_cli(
        "proxy",
        config_path,
        Some(target_id),
        stdin,
        Duration::from_secs(70),
    )
    .await
}

fn assert_proxy_response(output: &Output) -> Result<()> {
    ensure!(
        output.status.success(),
        "proxy CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = [SSH_BANNER, SSH_RESPONSE].concat();
    ensure!(
        output.stdout == expected,
        "proxy stdout differs from the SSH byte stream: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

async fn wait_for_tunnel_status(
    state: &super::super::ServerState,
    session_ids: &[Uuid],
    expected: &str,
) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            let mut all_expected = true;
            for session_id in session_ids {
                let status: Option<String> =
                    sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
                        .bind(session_id.to_string())
                        .fetch_optional(&state.inner.db.pool)
                        .await?;
                if status.as_deref() != Some(expected) {
                    all_expected = false;
                }
            }
            if all_expected {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("waiting for tunnel session status")??;
    Ok(())
}

#[tokio::test]
async fn client_auth_failure_is_terminal_for_online_ungranted_target() {
    let result = async {
        let server = LocalServer::start_at(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let device_key = SecretKey::generate();
        let (target_id, agent_token) =
            create_enrolled_target(server.state(), "route-auth-denied-target", &device_key).await;
        let config_path = server.client_config()?;
        let client_data_dir = server.fixture.data_dir.join("route-client-state");
        let profiles_dir = client_data_dir.join("profiles");
        let hash_component = |value: &str| URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()));
        let profile_dir = profiles_dir
            .join(hash_component(&server.issuer))
            .join(hash_component("route-acceptance"));
        fs::create_dir_all(&profile_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for directory in [
                client_data_dir.as_path(),
                profiles_dir.as_path(),
                profile_dir.as_path(),
            ] {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            }
        }
        let http = crate::transport::http_client(&server.tls)?;
        let tokens: LoginTokens = http
            .post(format!("{}/v1/auth/password", server.issuer))
            .json(&PasswordLoginRequest {
                username: ADMIN_USERNAME.to_owned(),
                password: ADMIN_PASSWORD.to_owned(),
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let saved_login = serde_json::json!({
            "server_url": server.issuer.clone(),
            "profile": "route-acceptance",
            "username": ADMIN_USERNAME,
            "tokens": tokens,
        });
        let login_path = profile_dir.join(format!("{}.json", hash_component(ADMIN_USERNAME)));
        fs::write(login_path, serde_json::to_vec(&saved_login)?)?;
        fs::write(profile_dir.join("active-user"), ADMIN_USERNAME)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                profile_dir.join(format!("{}.json", hash_component(ADMIN_USERNAME))),
                fs::Permissions::from_mode(0o600),
            )?;
            fs::set_permissions(
                profile_dir.join("active-user"),
                fs::Permissions::from_mode(0o600),
            )?;
        }

        let _agent_control =
            connect_control_ws(&server.issuer, "agent/control", &agent_token, &server.tls).await;
        wait_target_online(server.state(), target_id).await?;
        let has_grant: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM target_permissions WHERE target_id = ?1 \
             AND permission = 'ssh_connect')",
        )
        .bind(target_id.to_string())
        .fetch_one(&server.state().inner.db.pool)
        .await?;
        ensure!(
            has_grant == 0,
            "auth fast-stop fixture unexpectedly has ssh_connect"
        );
        let sessions_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tunnel_sessions")
            .fetch_one(&server.state().inner.db.pool)
            .await?;
        let error = client::run(Cli {
            config: Some(config_path),
            data_dir: None,
            profile: None,
            server_url: None,
            command: ClientCommand::Proxy { target_id },
        })
        .await
        .expect_err("online target without a grant must be denied");
        let error = format!("{error:#}");
        ensure!(
            error.contains("PrivateDirect")
                && !error.contains("PublicDirect")
                && !error.contains("PrivateRelay"),
            "authorization denial retried a later route: {error}"
        );
        ensure!(
            error.contains("forbidden") || error.contains("authorization"),
            "server did not classify the missing ssh_connect grant as authorization: {error}"
        );
        let sessions_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tunnel_sessions")
            .fetch_one(&server.state().inner.db.pool)
            .await?;
        ensure!(
            sessions_before == sessions_after,
            "authorization denial persisted a tunnel session"
        );
        eprintln!(
            "route_acceptance_auth_fast_stop target_id={target_id} mode=PrivateDirect retried=false grant=false tunnel_rows_before={sessions_before} tunnel_rows_after={sessions_after} error={error:?}"
        );
        server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        panic!("auth fast-stop acceptance failed: {error:#}");
    }
}

#[tokio::test]
#[ignore = "uses the SDK default QAD reflectors over UDP in the two direct attempts"]
async fn client_routes_real_direct_timeouts_to_private_relay_ssh_stream() {
    let result = async {
        let server = LocalServer::start().await?;
        let (target_id, agent_token, device_key) = enroll_and_grant_target(&server).await?;
        let config_path = server.client_config()?;
        login_client(&config_path).await?;

        let (ssh_addr, ssh_task) = start_ssh_fixture().await?;
        let (output, target_evidence) = tokio::join!(
            run_proxy(&config_path, target_id, SSH_REQUEST),
            drive_target(
                &server,
                target_id,
                agent_token,
                device_key,
                false,
                Some(ssh_addr),
            )
        );
        let output = output?;
        assert_proxy_response(&output)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            stderr.contains("SSH route PrivateDirect failed")
                && stderr.contains("SSH route PublicDirect failed"),
            "the real client did not report both direct attempts failing: {stderr}"
        );
        let target_evidence = target_evidence.context("target route fixture failed")?;
        ensure!(
            target_evidence.direct_attempts.len() == 2,
            "fixture did not observe both direct attempts: {:?}",
            target_evidence.direct_attempts
        );
        ensure!(
            target_evidence.direct_attempts[0].route_mode == RouteMode::PrivateDirect
                && target_evidence.direct_attempts[1].route_mode == RouteMode::PublicDirect,
            "direct attempts ran in an unexpected order"
        );
        for attempt in &target_evidence.direct_attempts {
            ensure!(
                attempt.target_qad_drop.datagrams > 0 && attempt.target_qad_drop.bytes > 0,
                "target QAD blackhole saw no packets"
            );
            ensure!(
                attempt.native_udp_drop.datagrams > 0 && attempt.native_udp_drop.bytes > 0,
                "native DirectOnly Iroh dial saw no blackhole packets"
            );
            ensure!(
                !attempt.native_dial_failure.is_empty(),
                "native Iroh dial did not report its actual blackhole timeout"
            );
        }
        let relay = target_evidence
            .relay_stream
            .context("private relay stream evidence is missing")?;
        ensure!(
            target_evidence.relay_session_id == Some(relay.session_id),
            "private relay session identity differs from the stream evidence"
        );
        let expected_relay_url = reqwest::Url::parse(&server.issuer)?.to_string();
        ensure!(
            relay.selected_url == expected_relay_url && relay.tx_delta > 0 && relay.rx_delta > 0,
            "private relay typed selected URL/counters do not match: {relay:?}"
        );
        ensure!(
            relay.selected_remote_address.contains(&expected_relay_url),
            "Iroh selected-path stats report a different private relay: {relay:?}"
        );
        let requested = timeout(Duration::from_secs(5), ssh_task)
            .await
            .context("SSH fixture did not finish")??
            .context("SSH fixture failed")?;
        ensure!(
            requested == SSH_REQUEST,
            "SSH fixture observed an unexpected request"
        );
        let session_ids = target_evidence
            .direct_attempts
            .iter()
            .map(|attempt| attempt.session_id)
            .chain(std::iter::once(relay.session_id))
            .collect::<Vec<_>>();
        ensure!(
            session_ids.iter().copied().collect::<HashSet<_>>().len() == 3,
            "direct retries and private relay did not use fresh session IDs"
        );
        wait_for_tunnel_status(server.state(), &session_ids, "closed").await?;
        let mut closed_rows = Vec::new();
        for session_id in &session_ids {
            let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
                .bind(session_id.to_string())
                .fetch_one(&server.state().inner.db.pool)
                .await?;
            closed_rows.push(format!("{session_id}:{status}"));
        }
        eprintln!(
            "route_acceptance_success sessions={session_ids:?} direct_attempts={:?} private_relay={relay:?} ssh_request={:?} ssh_request_bytes={} proxy_stdout_bytes={} db_rows={closed_rows:?} client_stderr={:?}",
            target_evidence.direct_attempts,
            String::from_utf8_lossy(&requested),
            requested.len(),
            output.stdout.len(),
            String::from_utf8_lossy(&output.stderr),
        );
        server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        panic!("route acceptance failed: {error:#}");
    }
}

#[tokio::test]
#[ignore = "uses the SDK default QAD reflectors over UDP in the two direct attempts"]
async fn client_reports_real_private_relay_refusal_after_direct_timeouts() {
    let result = async {
        let server = LocalServer::start().await?;
        let (target_id, agent_token, device_key) = enroll_and_grant_target(&server).await?;
        let config_path = server.client_config()?;
        login_client(&config_path).await?;
        let (output, target_evidence) = tokio::join!(
            run_proxy(&config_path, target_id, &[]),
            drive_target(&server, target_id, agent_token, device_key, true, None)
        );
        let output = output?;
        ensure!(
            !output.status.success(),
            "proxy succeeded after private relay refusal"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        let route_failures = stderr
            .lines()
            .filter(|line| line.contains("SSH route ") && line.contains(" failed after "))
            .collect::<Vec<_>>();
        ensure!(
            route_failures.len() == 3
                && route_failures[0].contains("PrivateDirect")
                && route_failures[1].contains("PublicDirect")
                && route_failures[2].contains("PrivateRelay"),
            "route failure sequence did not reach the private relay phase: {stderr}"
        );
        ensure!(
            stderr.contains("SSH route plan stopped")
                && stderr.contains("PrivateDirect session=")
                && stderr.contains("PublicDirect session="),
            "final error omitted the earlier direct route contexts: {stderr}"
        );
        ensure!(
            stderr.contains("denied") || stderr.contains("refused"),
            "final private relay failure lacks its authentication/refusal reason: {stderr}"
        );
        let target_evidence = target_evidence.context("target refusal fixture failed")?;
        ensure!(
            target_evidence.direct_attempts.len() == 2,
            "refusal test did not observe both direct attempts"
        );
        ensure!(
            server.access.denial_count.load(Ordering::Relaxed) > 0,
            "local Iroh relay did not refuse the actual client EndpointId"
        );
        ensure!(
            target_evidence.relay_refusal_stage.is_some(),
            "private relay refusal stage was not recorded"
        );
        let mut session_ids = target_evidence
            .direct_attempts
            .iter()
            .map(|attempt| attempt.session_id)
            .collect::<Vec<_>>();
        session_ids.push(
            target_evidence
                .relay_session_id
                .context("private relay SID was not reached")?,
        );
        ensure!(
            session_ids.iter().copied().collect::<HashSet<_>>().len() == 3,
            "failed route attempts reused a session ID"
        );
        for session_id in &session_ids {
            ensure!(
                stderr.contains(&session_id.to_string()),
                "final route error omitted session ID {session_id}: {stderr}"
            );
        }
        wait_for_tunnel_status(server.state(), &session_ids, "closed").await?;
        let active_sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tunnel_sessions WHERE status != 'closed'")
                .fetch_one(&server.state().inner.db.pool)
                .await?;
        ensure!(
            active_sessions == 0,
            "failed route left active or pending database sessions"
        );
        let mut closed_rows = Vec::new();
        for session_id in &session_ids {
            let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
                .bind(session_id.to_string())
                .fetch_one(&server.state().inner.db.pool)
                .await?;
            closed_rows.push(format!("{session_id}:{status}"));
        }
        eprintln!(
            "route_acceptance_all_failed sessions={session_ids:?} direct_attempts={:?} private_relay_refusal_stage={:?} relay_denials={} active_rows={active_sessions} db_rows={closed_rows:?} final_client_stderr={:?}",
            target_evidence.direct_attempts,
            target_evidence.relay_refusal_stage,
            server.access.denial_count.load(Ordering::Relaxed),
            String::from_utf8_lossy(&output.stderr),
        );
        server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        panic!("private relay refusal acceptance failed: {error:#}");
    }
}
