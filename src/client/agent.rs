use std::{
    collections::HashMap,
    fs, io,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use iroh::Watcher;
use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::Connection};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::sleep,
};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{
        AgentCredentials, AgentEnrollmentRequest, ControlMessage, RelayMode, TransportInfo,
        TunnelTicketClaims,
    },
    transport::{
        IrohByteStream, IrohEndpointOptions, RelayChoice, TransportError, accept_peer,
        create_endpoint,
    },
};

use super::{
    ClientContext,
    api::{Api, WsStream},
    profile::{self, write_json_atomic},
};

const CONTROL_RETRY_MAX: Duration = Duration::from_secs(30);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const RELAY_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(20);
const SESSION_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TICKET_FRAME: usize = 8 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingAgentIdentity {
    endpoint_secret_key: String,
}

struct TunnelOffer {
    session_id: Uuid,
    target_id: Uuid,
    ticket: String,
    client_endpoint_id: String,
    target_endpoint_addr: EndpointAddr,
    ticket_public_key_pem: String,
    relay_mode: RelayMode,
}

type EndpointMap = Arc<Mutex<HashMap<RelayMode, Endpoint>>>;
type PendingPeers = Arc<Mutex<HashMap<(RelayMode, String), mpsc::Sender<Connection>>>>;

struct AgentRuntime {
    endpoint_secret_key: SecretKey,
    transport_info: TransportInfo,
    endpoints: EndpointMap,
    pending_peers: PendingPeers,
    accept_tasks: JoinSet<()>,
    active_sessions: JoinSet<()>,
    completed_sessions: Arc<StdMutex<Vec<Uuid>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("agent connection authentication failed: {0}")]
struct AgentAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("server selected an authentication failure: {0}")]
struct ServerAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
enum TicketReadError {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("invalid ticket frame: {0}")]
    Invalid(String),
}

pub async fn enroll(context: &ClientContext, target_id: Uuid, enrollment_code: &str) -> Result<()> {
    let credential_path = profile::agent_credentials_path(&context.config.data_dir, target_id);
    let pending_path = credential_path.with_extension("pending.json");
    let identity = if credential_path.exists() {
        let saved = profile::load_agent_credentials(&context.config.data_dir, target_id)?;
        PendingAgentIdentity {
            endpoint_secret_key: saved.endpoint_secret_key,
        }
    } else {
        match fs::read(&pending_path) {
            Ok(bytes) => serde_json::from_slice::<PendingAgentIdentity>(&bytes)
                .context("read pending target Iroh identity")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = PendingAgentIdentity {
                    endpoint_secret_key: encode_secret_key(&SecretKey::generate()),
                };
                profile::ensure_private_dir(&context.config.data_dir)?;
                write_json_atomic(&pending_path, &identity)?;
                identity
            }
            Err(error) => return Err(error).context("read pending target Iroh identity"),
        }
    };
    let endpoint_secret_key = decode_secret_key(&identity.endpoint_secret_key)?;
    let response = context
        .api
        .agent_enroll(&AgentEnrollmentRequest {
            target_id,
            enrollment_token: enrollment_code.to_owned(),
            agent_endpoint_id: endpoint_secret_key.public().to_string(),
        })
        .await?;
    anyhow::ensure!(
        response.target_id == target_id,
        "server enrolled a different target ID"
    );
    profile::save_agent_credentials(
        &context.config.data_dir,
        &AgentCredentials {
            target_id,
            agent_token: response.agent_token,
            ticket_public_key_pem: response.ticket_public_key_pem,
            endpoint_secret_key: identity.endpoint_secret_key,
        },
    )?;
    if pending_path.exists() {
        fs::remove_file(pending_path).context("remove completed pending Iroh identity")?;
    }
    Ok(())
}

pub async fn run(context: &ClientContext, target_id: Uuid) -> Result<()> {
    let credentials = profile::load_agent_credentials(&context.config.data_dir, target_id)?;
    let mut runtime = AgentRuntime {
        endpoint_secret_key: decode_secret_key(&credentials.endpoint_secret_key)?,
        transport_info: context.api.transport_info().await?,
        endpoints: Arc::new(Mutex::new(HashMap::new())),
        pending_peers: Arc::new(Mutex::new(HashMap::new())),
        accept_tasks: JoinSet::new(),
        active_sessions: JoinSet::new(),
        completed_sessions: Arc::new(StdMutex::new(Vec::new())),
    };
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match control_session(context, &credentials, &mut runtime).await {
            Ok(()) => bail!("agent control connection closed"),
            Err(error) if is_authentication_error(&error) => {
                tracing::error!(target = %target_id, error = %error, "agent credential was rejected; active SSH sessions will finish");
                while let Some(result) = runtime.active_sessions.join_next().await {
                    if let Err(error) = result {
                        tracing::warn!(target = %target_id, error = %error, "active SSH session ended");
                    }
                }
                runtime.accept_tasks.abort_all();
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(target = %target_id, error = %error, retry_seconds = retry_delay.as_secs(), "agent control connection lost; active SSH sessions remain connected");
                sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(CONTROL_RETRY_MAX);
            }
        }
    }
}

fn endpoint_options(
    context: &ClientContext,
    info: &TransportInfo,
    relay_mode: RelayMode,
) -> Result<IrohEndpointOptions> {
    let relay_choice = match relay_mode {
        RelayMode::Private => {
            let relay_url = info
                .private_relay_url
                .as_deref()
                .context("private Iroh relay is not configured")?;
            let relay_url =
                reqwest::Url::parse(relay_url).context("parse private Iroh relay URL")?;
            let control_origin = reqwest::Url::parse(context.api.issuer())
                .context("parse configured kmesh server URL")?;
            anyhow::ensure!(
                relay_url == control_origin,
                "Iroh private relay URL differs from the configured kmesh server"
            );
            RelayChoice::Private {
                url: relay_url,
                qad_port: info.qad_port,
            }
        }
        RelayMode::PublicDefault => RelayChoice::PublicDefault,
    };
    Ok(IrohEndpointOptions {
        relay_choice,
        tls: context.config.tls.clone(),
    })
}

fn encode_secret_key(secret_key: &SecretKey) -> String {
    URL_SAFE_NO_PAD.encode(secret_key.to_bytes())
}

fn decode_secret_key(encoded: &str) -> Result<SecretKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode saved target Iroh secret key")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("saved target Iroh secret key must contain 32 bytes"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

async fn send_control_sink(
    writer: &mut futures_util::stream::SplitSink<WsStream, Message>,
    message: &ControlMessage,
) -> Result<()> {
    let text = serde_json::to_string(message).context("encode agent control message")?;
    writer
        .send(Message::Text(text.into()))
        .await
        .context("send agent control message")
}

async fn accept_connections(
    endpoint: Endpoint,
    relay_mode: RelayMode,
    pending_peers: PendingPeers,
) {
    loop {
        let connection = match accept_peer(&endpoint).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, "accepting Iroh SSH connection failed");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let remote_id = connection.remote_id().to_string();
        let sender = pending_peers
            .lock()
            .await
            .get(&(relay_mode, remote_id.clone()))
            .cloned();
        if let Some(sender) = sender
            && sender.send(connection).await.is_err()
        {
            tracing::debug!(remote = %remote_id, "Iroh connection arrived after its offer expired");
        }
    }
}

async fn prepare_endpoint(
    context: &ClientContext,
    endpoint_secret_key: &SecretKey,
    transport_info: &TransportInfo,
    relay_mode: RelayMode,
    endpoints: &EndpointMap,
    pending_peers: &PendingPeers,
    accept_tasks: &mut JoinSet<()>,
) -> std::result::Result<EndpointAddr, TransportError> {
    let endpoint = {
        let mut endpoints = endpoints.lock().await;
        if let Some(endpoint) = endpoints.get(&relay_mode).cloned() {
            endpoint
        } else {
            let options = endpoint_options(context, transport_info, relay_mode)
                .map_err(|error| TransportError::Configuration(error.to_string()))?;
            let endpoint = create_endpoint(endpoint_secret_key.clone(), true, options).await?;
            endpoints.insert(relay_mode, endpoint.clone());
            let accept_endpoint = endpoint.clone();
            let accept_peers = pending_peers.clone();
            accept_tasks.spawn(async move {
                accept_connections(accept_endpoint, relay_mode, accept_peers).await;
            });
            endpoint
        }
    };
    wait_endpoint_online(&endpoint).await?;
    Ok(endpoint.addr())
}

async fn wait_endpoint_online(endpoint: &Endpoint) -> std::result::Result<(), TransportError> {
    let deadline = tokio::time::Instant::now() + RELAY_ENDPOINT_TIMEOUT;
    let mut status = endpoint.home_relay_status();
    loop {
        let relays = status.get();
        if relays.iter().any(|relay| relay.is_connected()) {
            return Ok(());
        }
        if let Some(reason) = relays.iter().find_map(|relay| relay.auth_denied_reason()) {
            return Err(TransportError::Authentication(reason.to_owned()));
        }
        if let Some(error) = relays
            .iter()
            .filter_map(|relay| relay.last_error())
            .find(|error| crate::transport::is_auth_failure_source(*error))
        {
            return Err(TransportError::Authentication(error.to_string()));
        }
        tokio::select! {
            update = status.updated() => {
                if update.is_err() {
                    return Err(TransportError::EndpointClosed);
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(TransportError::Timeout("target Iroh relay registration"));
            }
        }
    }
}

async fn control_session(
    context: &ClientContext,
    credentials: &AgentCredentials,
    runtime: &mut AgentRuntime,
) -> Result<()> {
    let ws = tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        context.api.agent_control(&credentials.agent_token),
    )
    .await
    .context("agent control connection timed out")??;
    let (mut writer, mut reader) = ws.split();
    let completed = {
        let mut completed = runtime
            .completed_sessions
            .lock()
            .expect("completed session lock poisoned");
        std::mem::take(&mut *completed)
    };
    for session_id in completed {
        send_control_sink(
            &mut writer,
            &ControlMessage::Close {
                session_id,
                reason: "session_finished_while_control_was_offline".to_owned(),
            },
        )
        .await
        .context("report SSH session finished while control was offline")?;
    }
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<ControlMessage>(64);
    let (done_tx, mut done_rx) = mpsc::channel::<Uuid>(16);
    let mut sessions: HashMap<Uuid, mpsc::Sender<ControlMessage>> = HashMap::new();
    loop {
        tokio::select! {
            Some(message) = outbound_rx.recv() => {
                send_control_sink(&mut writer, &message).await.context("send agent control message")?;
            }
            Some(session_id) = done_rx.recv() => {
                sessions.remove(&session_id);
            }
            joined = runtime.active_sessions.join_next(), if !runtime.active_sessions.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(error = %error, "active SSH session task failed");
                }
            }
            incoming = reader.next() => {
                let Some(incoming) = incoming else { bail!("agent control WebSocket ended") };
                let incoming = incoming.context("read agent control WebSocket")?;
                if matches!(incoming, Message::Ping(_) | Message::Pong(_)) {
                    continue;
                }
                match Api::control_message(incoming)? {
                    ControlMessage::Prepare { session_id, relay_mode } => {
                        match prepare_endpoint(
                            context,
                            &runtime.endpoint_secret_key,
                            &runtime.transport_info,
                            relay_mode,
                            &runtime.endpoints,
                            &runtime.pending_peers,
                            &mut runtime.accept_tasks,
                        ).await {
                            Ok(endpoint_addr) => {
                                send_control_sink(&mut writer, &ControlMessage::AgentReady {
                                    session_id: Some(session_id),
                                    relay_mode,
                                    endpoint_addr,
                                }).await.context("publish prepared Iroh endpoint to server")?;
                            }
                            Err(error) => {
                                let code = if error.is_security_failure() || error.is_auth_failure() {
                                    "authentication"
                                } else if matches!(error, TransportError::Configuration(_) | TransportError::Tls(_)) {
                                    "configuration"
                                } else if error.is_network_failure() {
                                    "network"
                                } else {
                                    "configuration"
                                };
                                outbound_tx.send(ControlMessage::Error {
                                    session_id: Some(session_id),
                                    code: code.to_owned(),
                                    message: error.to_string(),
                                }).await.context("report target relay preparation failure")?;
                            }
                        }
                    }
                    ControlMessage::Offer {
                        session_id,
                        target_id,
                        ticket,
                        client_endpoint_id,
                        target_endpoint_addr,
                        ticket_public_key_pem,
                        relay_mode,
                    } => {
                        let offer = TunnelOffer {
                            session_id,
                            target_id,
                            ticket,
                            client_endpoint_id,
                            target_endpoint_addr,
                            ticket_public_key_pem,
                            relay_mode,
                        };
                        let claims = decode_tunnel_ticket(
                            &offer.ticket,
                            &offer.ticket_public_key_pem,
                            context.api.issuer(),
                        )
                        .map_err(|error| AgentAuthenticationFailure(error.to_string()));
                        let validation = claims
                            .map_err(anyhow::Error::new)
                            .and_then(|claims| validate_ticket(&claims, &offer, credentials));
                        if let Err(error) = validation {
                            outbound_tx.send(ControlMessage::Error {
                                session_id: Some(session_id),
                                code: "authentication".to_owned(),
                                message: error.to_string(),
                            }).await.context("report invalid signed tunnel offer")?;
                            continue;
                        }
                        let endpoint = runtime.endpoints.lock().await.get(&relay_mode).cloned()
                            .context("offer relay endpoint has not been prepared")?;
                        let relay_choice = match endpoint_options(context, &runtime.transport_info, relay_mode) {
                            Ok(options) => options.relay_choice,
                            Err(error) => {
                                outbound_tx.send(ControlMessage::Error {
                                    session_id: Some(session_id),
                                    code: "configuration".to_owned(),
                                    message: error.to_string(),
                                }).await.context("report target relay configuration failure")?;
                                continue;
                            }
                        };
                        if let Err(error) = crate::transport::validate_endpoint_addr(
                            &offer.target_endpoint_addr,
                            &relay_choice,
                        ) {
                            outbound_tx.send(ControlMessage::Error {
                                session_id: Some(session_id),
                                code: "authentication".to_owned(),
                                message: error.to_string(),
                            }).await.context("reject untrusted target relay address")?;
                            continue;
                        }
                        if offer.target_endpoint_addr.id != endpoint.id() {
                            outbound_tx.send(ControlMessage::Error {
                                session_id: Some(session_id),
                                code: "authentication".to_owned(),
                                message: "offer EndpointId differs from this agent".to_owned(),
                            }).await.context("reject offer for another target EndpointId")?;
                            continue;
                        }
                        anyhow::ensure!(!sessions.contains_key(&session_id), "duplicate offer for session {session_id}");
                        let (peer_tx, peer_rx) = mpsc::channel(1);
                        {
                            let mut peers = runtime.pending_peers.lock().await;
                            anyhow::ensure!(peers.insert((relay_mode, offer.client_endpoint_id.clone()), peer_tx).is_none(), "client EndpointId already has a pending offer");
                        }
                        let (session_tx, session_rx) = mpsc::channel(16);
                        sessions.insert(session_id, session_tx);
                        let context = context.clone();
                        let outbound_tx = outbound_tx.clone();
                        let done_tx = done_tx.clone();
                        let completed_sessions = runtime.completed_sessions.clone();
                        let pending_peers = runtime.pending_peers.clone();
                        runtime.active_sessions.spawn(async move {
                            let peer_endpoint_id = offer.client_endpoint_id.clone();
                            let result = handle_offer(
                                &context,
                                offer,
                                peer_rx,
                                session_rx,
                                outbound_tx.clone(),
                            )
                            .await;
                            if let Err(error) = result {
                                let code = if is_authentication_error(&error) { "authentication" } else { "network" };
                                tracing::warn!(session = %session_id, error = %error, "target SSH session failed");
                                if outbound_tx.send(ControlMessage::Error {
                                    session_id: Some(session_id),
                                    code: code.to_owned(),
                                    message: error.to_string(),
                                }).await.is_err() {
                                    remember_completed(&completed_sessions, session_id);
                                }
                            }
                            pending_peers
                                .lock()
                                .await
                                .remove(&(relay_mode, peer_endpoint_id));
                            let _ = done_tx.send(session_id).await;
                        });
                        send_control_sink(&mut writer, &ControlMessage::OfferReady { session_id, relay_mode })
                            .await.context("confirm target is ready for Iroh connection")?;
                    }
                    ControlMessage::Error { session_id: None, code, message }
                        if code == "authentication" || code == "authorization" =>
                    {
                        return Err(anyhow!(ServerAuthenticationFailure(format!("server rejected agent control: {message}"))));
                    }
                    message => {
                        if let Some(session_id) = message_session_id(&message)
                            && let Some(sender) = sessions.get(&session_id)
                        {
                            sender.send(message).await.context("route agent session message")?;
                        }
                    }
                }
            }
        }
    }
}

async fn handle_offer(
    context: &ClientContext,
    offer: TunnelOffer,
    mut peer_rx: mpsc::Receiver<Connection>,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let connection = tokio::time::timeout(SESSION_SETUP_TIMEOUT, async {
        tokio::select! {
            biased;
            control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
                control.map(|()| None)
            },
            connection = peer_rx.recv() => connection.context("agent peer listener stopped").map(Some),
        }
    })
        .await
        .context("timed out waiting for the authenticated Iroh peer")?
        ?;
    let Some(connection) = connection else {
        return Ok(());
    };
    let remote_endpoint_id = connection.remote_id().to_string();
    ensure_auth(
        remote_endpoint_id == offer.client_endpoint_id,
        "Iroh peer EndpointId differs from the ticket client EndpointId",
    )?;

    let mut stream = tokio::select! {
        biased;
        control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
            control?;
            return Ok(());
        },
        result = IrohByteStream::accept_bi(connection) => result.map_err(transport_error)?,
    };
    let ticket_in_stream = tokio::select! {
        biased;
        control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
            control?;
            return Ok(());
        },
        result = read_ticket(&mut stream) => result.map_err(|error| match error {
            TicketReadError::Io { .. } => anyhow!(error),
            TicketReadError::Invalid(message) => anyhow!(AgentAuthenticationFailure(message)),
        })?,
    };
    ensure_auth(
        ticket_in_stream == offer.ticket,
        "Iroh stream ticket differs from its offer",
    )?;
    outbound
        .send(ControlMessage::IrohReady {
            session_id: offer.session_id,
            client_endpoint_id: remote_endpoint_id,
            relay_mode: offer.relay_mode,
        })
        .await
        .context("report authenticated Iroh peer to server")?;
    if !wait_activated(offer.session_id, &mut control_rx).await? {
        return Ok(());
    }

    let mut ssh = tokio::time::timeout(
        Duration::from_secs(context.config.ssh.connect_timeout_secs),
        TcpStream::connect(context.config.ssh.address),
    )
    .await
    .context("connecting to local sshd timed out")?
    .with_context(|| format!("connect to local sshd at {}", context.config.ssh.address))?;
    ssh.set_nodelay(true)
        .context("set local sshd TCP_NODELAY")?;
    let result = tokio::io::copy_bidirectional(&mut ssh, &mut stream).await;
    match result {
        Ok((to_ssh, from_ssh)) => {
            stream
                .finish_send_and_wait()
                .await
                .context("wait for client to acknowledge final SSH bytes")?;
            stream
                .connection()
                .close(iroh::endpoint::VarInt::from_u32(0), b"ssh session complete");
            tracing::debug!(session = %offer.session_id, to_ssh, from_ssh, "target SSH stream completed");
            outbound
                .send(ControlMessage::Close {
                    session_id: offer.session_id,
                    reason: "ssh_stream_complete".to_owned(),
                })
                .await
                .context("report completed SSH stream")?;
            Ok(())
        }
        Err(error) => {
            let _ = stream.reset();
            Err(error).context("copy SSH data between Iroh and local sshd")
        }
    }
}

async fn wait_for_setup_cancellation(
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
) -> Result<()> {
    loop {
        match inbound.recv().await {
            None => return Ok(()),
            Some(ControlMessage::Close {
                session_id: received,
                ..
            }) if received == session_id => return Ok(()),
            Some(ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            }) if received == session_id => {
                if code == "authentication" || code == "authorization" {
                    bail!(AgentAuthenticationFailure(message));
                }
                bail!("server rejected SSH session during setup: {message}");
            }
            Some(_) => {}
        }
    }
}

fn validate_ticket(
    claims: &TunnelTicketClaims,
    offer: &TunnelOffer,
    credentials: &AgentCredentials,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    ensure_auth(
        offer.ticket_public_key_pem == credentials.ticket_public_key_pem,
        "ticket public key differs from enrollment",
    )?;
    ensure_auth(
        claims.session_id == offer.session_id,
        "ticket session ID mismatch",
    )?;
    ensure_auth(
        claims.target_id == offer.target_id,
        "ticket target ID mismatch",
    )?;
    ensure_auth(
        claims.client_endpoint_id == offer.client_endpoint_id,
        "ticket client EndpointId mismatch",
    )?;
    ensure_auth(
        claims.target_endpoint_id == offer.target_endpoint_addr.id.to_string(),
        "ticket target EndpointId mismatch",
    )?;
    ensure_auth(
        claims.relay_mode == offer.relay_mode,
        "ticket relay mode mismatch",
    )?;
    ensure_auth(
        offer.target_id == credentials.target_id,
        "offer target ID differs from enrolled target",
    )?;
    ensure_auth(
        claims.aud == TUNNEL_TICKET_AUDIENCE,
        "ticket audience mismatch",
    )?;
    ensure_auth(claims.exp > now, "ticket has expired")?;
    offer
        .client_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(AgentAuthenticationFailure(
                "client EndpointId is invalid".to_owned()
            ))
        })?;
    claims
        .target_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(AgentAuthenticationFailure(
                "target EndpointId is invalid".to_owned()
            ))
        })?;
    Ok(())
}

async fn wait_activated(
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
) -> Result<bool> {
    loop {
        match inbound.recv().await {
            None => return Ok(false),
            Some(ControlMessage::Activated {
                session_id: received,
            }) if received == session_id => return Ok(true),
            Some(ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            }) if received == session_id => {
                if code == "authentication" || code == "authorization" {
                    bail!(AgentAuthenticationFailure(message));
                }
                bail!("server rejected SSH session before activation: {message}");
            }
            Some(ControlMessage::Close {
                session_id: received,
                ..
            }) if received == session_id => return Ok(false),
            Some(_) => {}
        }
    }
}

async fn read_ticket(stream: &mut IrohByteStream) -> std::result::Result<String, TicketReadError> {
    let mut length_bytes = [0; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .map_err(|source| TicketReadError::Io {
            context: "read ticket frame length",
            source,
        })?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_TICKET_FRAME {
        return Err(TicketReadError::Invalid(
            "ticket frame length is invalid".to_owned(),
        ));
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|source| TicketReadError::Io {
            context: "read ticket frame",
            source,
        })?;
    String::from_utf8(bytes)
        .map_err(|error| TicketReadError::Invalid(format!("ticket frame is not UTF-8: {error}")))
}

fn message_session_id(message: &ControlMessage) -> Option<Uuid> {
    match message {
        ControlMessage::Activated { session_id }
        | ControlMessage::IrohReady { session_id, .. }
        | ControlMessage::OfferReady { session_id, .. }
        | ControlMessage::Prepare { session_id, .. }
        | ControlMessage::Close { session_id, .. } => Some(*session_id),
        ControlMessage::Error { session_id, .. } => *session_id,
        ControlMessage::Open { .. }
        | ControlMessage::Offer { .. }
        | ControlMessage::AgentReady {
            session_id: None, ..
        } => None,
        ControlMessage::AgentReady {
            session_id: Some(session_id),
            ..
        } => Some(*session_id),
    }
}

fn remember_completed(completed: &Arc<StdMutex<Vec<Uuid>>>, session_id: Uuid) {
    let mut completed = completed.lock().expect("completed session lock poisoned");
    if !completed.contains(&session_id) {
        completed.push(session_id);
    }
}

pub(super) fn ensure_auth(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(AgentAuthenticationFailure(message.to_owned())))
    }
}

fn is_authentication_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AgentAuthenticationFailure>().is_some()
        || error
            .downcast_ref::<ServerAuthenticationFailure>()
            .is_some()
}

fn transport_error(error: TransportError) -> anyhow::Error {
    match error {
        TransportError::Authentication(message) => anyhow!(AgentAuthenticationFailure(message)),
        error => anyhow!(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{Endpoint, SecretKey, endpoint::presets};
    use tokio::io::AsyncWriteExt;

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

    async fn local_iroh_connections() -> (Endpoint, Endpoint, Connection, Connection) {
        let target = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![crate::transport::IROH_SSH_ALPN.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind local target Iroh endpoint");
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![crate::transport::IROH_SSH_ALPN.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind local client Iroh endpoint");

        let target_accept = {
            let target = target.clone();
            tokio::spawn(async move {
                target
                    .accept()
                    .await
                    .expect("target endpoint closed")
                    .await
                    .expect("accept local client connection")
            })
        };
        let client_connection = tokio::time::timeout(
            Duration::from_secs(5),
            client.connect(target.addr(), crate::transport::IROH_SSH_ALPN),
        )
        .await
        .expect("local Iroh connection timed out")
        .expect("connect local Iroh endpoints");
        let target_connection = tokio::time::timeout(Duration::from_secs(5), target_accept)
            .await
            .expect("target Iroh accept timed out")
            .expect("target accept task failed");
        (target, client, target_connection, client_connection)
    }

    fn offer(client_endpoint_id: String, ticket: &str) -> TunnelOffer {
        TunnelOffer {
            session_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            ticket: ticket.to_owned(),
            client_endpoint_id,
            target_endpoint_addr: EndpointAddr::new(SecretKey::generate().public()),
            ticket_public_key_pem: String::new(),
            relay_mode: RelayMode::Private,
        }
    }

    async fn await_offer(task: tokio::task::JoinHandle<Result<()>>) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("agent offer did not finish promptly")
            .expect("agent offer task panicked")
    }

    async fn handle_connected_offer(
        context: &ClientContext,
        offer: TunnelOffer,
        target_connection: Connection,
    ) -> Result<()> {
        let (peer_tx, peer_rx) = mpsc::channel(1);
        peer_tx
            .send(target_connection)
            .await
            .expect("route local peer connection to agent");
        let (_control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        handle_offer(context, offer, peer_rx, control_rx, outbound).await
    }

    #[tokio::test]
    async fn relay_mode_uses_public_default_only_when_requested() {
        let context = context("https://kmesh.test:9443").await;
        let info = TransportInfo {
            private_relay_url: None,
            qad_port: 3478,
        };

        let public = endpoint_options(&context, &info, RelayMode::PublicDefault)
            .expect("public relay mode does not require a private relay");
        assert_eq!(public.relay_choice, RelayChoice::PublicDefault);
        assert!(endpoint_options(&context, &info, RelayMode::Private).is_err());
    }

    #[tokio::test]
    async fn private_relay_must_match_the_authenticated_service_origin() {
        let context = context("https://kmesh.test:9443").await;
        let info = TransportInfo {
            private_relay_url: Some("https://kmesh.test:9443".to_owned()),
            qad_port: 3478,
        };
        let options = endpoint_options(&context, &info, RelayMode::Private)
            .expect("server private relay matches the control service");
        assert_eq!(
            options.relay_choice,
            RelayChoice::Private {
                url: reqwest::Url::parse("https://kmesh.test:9443").unwrap(),
                qad_port: 3478,
            }
        );

        let malicious = TransportInfo {
            private_relay_url: Some("https://untrusted.example".to_owned()),
            qad_port: 3478,
        };
        assert!(endpoint_options(&context, &malicious, RelayMode::Private).is_err());
    }

    #[tokio::test]
    async fn close_cancels_waiting_for_peer() {
        let context = context("https://kmesh.test:9443").await;
        let offer = offer("client-endpoint".to_owned(), "ticket");
        let session_id = offer.session_id;
        let (_peer_tx, peer_rx) = mpsc::channel(1);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_offer(&context, offer, peer_rx, control_rx, outbound).await
        });

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
    async fn control_disconnect_cancels_waiting_for_peer() {
        let context = context("https://kmesh.test:9443").await;
        let offer = offer("client-endpoint".to_owned(), "ticket");
        let (_peer_tx, peer_rx) = mpsc::channel(1);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_offer(&context, offer, peer_rx, control_rx, outbound).await
        });

        drop(control_tx);
        assert!(await_offer(task).await.is_ok());
    }

    #[tokio::test]
    async fn close_cancels_waiting_for_ticket_bytes() {
        let context = context("https://kmesh.test:9443").await;
        let (target, _client, target_connection, client_connection) =
            local_iroh_connections().await;
        let mut client_stream = IrohByteStream::open_bi(client_connection.clone())
            .await
            .expect("open local client stream");
        client_stream
            .write_u32(32)
            .await
            .expect("write ticket frame length");
        client_stream
            .write_all(b"partial")
            .await
            .expect("write partial ticket frame");
        client_stream
            .flush()
            .await
            .expect("flush partial ticket frame");

        let offer = offer(target_connection.remote_id().to_string(), "expected-ticket");
        let session_id = offer.session_id;
        let (peer_tx, peer_rx) = mpsc::channel(1);
        peer_tx
            .send(target_connection)
            .await
            .expect("route local peer connection to agent");
        drop(peer_tx);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_offer(&context, offer, peer_rx, control_rx, outbound).await
        });
        // The frame is incomplete, so after the local stream is accepted the agent blocks in read_ticket.
        tokio::time::sleep(Duration::from_millis(100)).await;
        control_tx
            .send(ControlMessage::Close {
                session_id,
                reason: "cancelled".to_owned(),
            })
            .await
            .expect("send session close");
        assert!(await_offer(task).await.is_ok());
        drop(client_stream);
        drop(target);
    }

    #[tokio::test]
    async fn close_cancels_waiting_for_bidirectional_stream() {
        let context = context("https://kmesh.test:9443").await;
        let (target, _client, target_connection, client_connection) =
            local_iroh_connections().await;
        let offer = offer(target_connection.remote_id().to_string(), "expected-ticket");
        let session_id = offer.session_id;
        let (peer_tx, peer_rx) = mpsc::channel(1);
        peer_tx
            .send(target_connection)
            .await
            .expect("route local peer connection to agent");
        drop(peer_tx);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_offer(&context, offer, peer_rx, control_rx, outbound).await
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        control_tx
            .send(ControlMessage::Close {
                session_id,
                reason: "cancelled".to_owned(),
            })
            .await
            .expect("send session close");
        assert!(await_offer(task).await.is_ok());
        drop(client_connection);
        drop(target);
    }

    #[tokio::test]
    async fn ticket_stream_disconnect_is_a_network_error() {
        let context = context("https://kmesh.test:9443").await;
        let (target, _client, target_connection, client_connection) =
            local_iroh_connections().await;
        let mut client_stream = IrohByteStream::open_bi(client_connection.clone())
            .await
            .expect("open local client stream");
        client_stream
            .write_u32(32)
            .await
            .expect("write ticket frame length");
        client_stream
            .write_all(b"partial")
            .await
            .expect("write partial ticket frame");
        client_stream
            .flush()
            .await
            .expect("flush partial ticket frame");

        let offer = offer(target_connection.remote_id().to_string(), "expected-ticket");
        let (peer_tx, peer_rx) = mpsc::channel(1);
        peer_tx
            .send(target_connection)
            .await
            .expect("route local peer connection to agent");
        let (control_tx, control_rx) = mpsc::channel(1);
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            handle_offer(&context, offer, peer_rx, control_rx, outbound).await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        client_stream.reset().expect("reset partial ticket stream");

        let error = await_offer(task)
            .await
            .expect_err("truncated ticket stream must fail");
        assert!(
            !is_authentication_error(&error),
            "stream reset was classified as authentication: {error:#}"
        );
        assert!(
            crate::transport::is_network_failure_source(error.as_ref()),
            "stream reset did not preserve a classifiable network source: {error:#}"
        );
        drop(control_tx);
        drop(target);
    }

    #[tokio::test]
    async fn invalid_frame_ticket_and_peer_identity_remain_authentication_errors() {
        let context = context("https://kmesh.test:9443").await;
        let (target, _client, target_connection, client_connection) =
            local_iroh_connections().await;
        let client_endpoint_id = target_connection.remote_id().to_string();

        let error = handle_connected_offer(
            &context,
            offer("different-endpoint".to_owned(), "expected-ticket"),
            target_connection.clone(),
        )
        .await
        .expect_err("wrong peer EndpointId must fail authentication");
        assert!(is_authentication_error(&error), "{error:#}");

        let mut invalid_frame = IrohByteStream::open_bi(client_connection.clone())
            .await
            .expect("open client stream for invalid frame");
        invalid_frame
            .write_u32(0)
            .await
            .expect("write invalid ticket frame length");
        invalid_frame.flush().await.expect("flush invalid frame");
        let error = handle_connected_offer(
            &context,
            offer(client_endpoint_id.clone(), "expected-ticket"),
            target_connection.clone(),
        )
        .await
        .expect_err("invalid ticket frame must fail authentication");
        assert!(is_authentication_error(&error), "{error:#}");

        let mut wrong_ticket = IrohByteStream::open_bi(client_connection.clone())
            .await
            .expect("open client stream for mismatched ticket");
        wrong_ticket
            .write_u32(5)
            .await
            .expect("write ticket frame length");
        wrong_ticket
            .write_all(b"wrong")
            .await
            .expect("write mismatched ticket");
        wrong_ticket.flush().await.expect("flush mismatched ticket");
        let error = handle_connected_offer(
            &context,
            offer(client_endpoint_id, "expected-ticket"),
            target_connection,
        )
        .await
        .expect_err("ticket differing from the signed offer must fail authentication");
        assert!(is_authentication_error(&error), "{error:#}");
        drop(target);
    }

    #[tokio::test]
    async fn close_or_control_disconnect_before_activation_is_cancellation() {
        let session_id = Uuid::new_v4();
        let (close_tx, mut close_rx) = mpsc::channel(1);
        close_tx
            .send(ControlMessage::Close {
                session_id,
                reason: "cancelled".to_owned(),
            })
            .await
            .expect("send session close");
        assert!(
            !wait_activated(session_id, &mut close_rx)
                .await
                .expect("close is a clean cancellation")
        );

        let (disconnected_tx, mut disconnected_rx) = mpsc::channel(1);
        drop(disconnected_tx);
        assert!(
            !wait_activated(session_id, &mut disconnected_rx)
                .await
                .expect("control disconnect is a clean cancellation")
        );
    }
}
