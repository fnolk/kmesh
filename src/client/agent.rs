use std::{
    collections::HashMap,
    fs,
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
        AgentCredentials, AgentEnrollmentRequest, ControlMessage, TransportInfo, TunnelTicketClaims,
    },
    transport::{
        IrohByteStream, IrohEndpointOptions, TransportError, accept_peer, create_endpoint,
    },
};

use super::{
    ClientContext,
    api::{Api, WsStream},
    profile::{self, write_json_atomic},
};

const CONTROL_RETRY_MAX: Duration = Duration::from_secs(30);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
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
}

#[derive(Debug, thiserror::Error)]
#[error("agent connection authentication failed: {0}")]
struct AgentAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("server selected an authentication failure: {0}")]
struct ServerAuthenticationFailure(String);

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
    let endpoint_secret_key = decode_secret_key(&credentials.endpoint_secret_key)?;
    let transport_info = context.api.transport_info().await?;
    let endpoint = create_endpoint(
        endpoint_secret_key,
        true,
        endpoint_options(&context, transport_info)?,
    )
    .await
    .map_err(anyhow::Error::new)
    .context("create target Iroh endpoint")?;

    let pending_peers = Arc::new(Mutex::new(
        HashMap::<String, mpsc::Sender<Connection>>::new(),
    ));
    let accept_endpoint = endpoint.clone();
    let accept_peers = pending_peers.clone();
    let accept_task =
        tokio::spawn(async move { accept_connections(accept_endpoint, accept_peers).await });
    let mut active_sessions = JoinSet::new();
    let completed_sessions = Arc::new(StdMutex::new(Vec::<Uuid>::new()));
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match control_session(
            context,
            &credentials,
            &endpoint,
            &pending_peers,
            &mut active_sessions,
            &completed_sessions,
        )
        .await
        {
            Ok(()) => bail!("agent control connection closed"),
            Err(error) if is_authentication_error(&error) => {
                tracing::error!(target = %target_id, error = %error, "agent credential was rejected; active SSH sessions will finish");
                while let Some(result) = active_sessions.join_next().await {
                    if let Err(error) = result {
                        tracing::warn!(target = %target_id, error = %error, "active SSH session ended");
                    }
                }
                accept_task.abort();
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

fn endpoint_options(context: &ClientContext, info: TransportInfo) -> Result<IrohEndpointOptions> {
    let relay_url = reqwest::Url::parse(&info.relay_url).context("parse Iroh relay URL")?;
    let control_origin =
        reqwest::Url::parse(context.api.issuer()).context("parse configured kmesh server URL")?;
    anyhow::ensure!(
        relay_url == control_origin,
        "Iroh relay URL differs from the configured kmesh server"
    );
    Ok(IrohEndpointOptions {
        relay_url,
        qad_port: info.qad_port,
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
    pending_peers: Arc<Mutex<HashMap<String, mpsc::Sender<Connection>>>>,
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
        let sender = pending_peers.lock().await.get(&remote_id).cloned();
        if let Some(sender) = sender {
            if sender.send(connection).await.is_err() {
                tracing::debug!(remote = %remote_id, "Iroh connection arrived after its offer expired");
            }
        }
    }
}

async fn control_session(
    context: &ClientContext,
    credentials: &AgentCredentials,
    endpoint: &Endpoint,
    pending_peers: &Arc<Mutex<HashMap<String, mpsc::Sender<Connection>>>>,
    active_sessions: &mut JoinSet<()>,
    completed_sessions: &Arc<StdMutex<Vec<Uuid>>>,
) -> Result<()> {
    let ws = tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        context.api.agent_control(&credentials.agent_token),
    )
    .await
    .context("agent control connection timed out")??;
    let (mut writer, mut reader) = ws.split();
    let mut endpoint_addrs = endpoint.watch_addr().stream();
    endpoint_addrs.next().await;
    let completed = {
        let mut completed = completed_sessions
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
    send_control_sink(
        &mut writer,
        &ControlMessage::AgentReady {
            endpoint_addr: endpoint.addr(),
        },
    )
    .await
    .context("publish target Iroh endpoint address")?;

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<ControlMessage>(64);
    let (done_tx, mut done_rx) = mpsc::channel::<Uuid>(16);
    let mut sessions: HashMap<Uuid, mpsc::Sender<ControlMessage>> = HashMap::new();
    loop {
        tokio::select! {
            address = endpoint_addrs.next() => {
                let address = address.context("target Iroh address watcher stopped")?;
                send_control_sink(&mut writer, &ControlMessage::AgentReady { endpoint_addr: address })
                    .await.context("publish updated target Iroh address")?;
            }
            Some(message) = outbound_rx.recv() => {
                send_control_sink(&mut writer, &message).await.context("send agent control message")?;
            }
            Some(session_id) = done_rx.recv() => {
                sessions.remove(&session_id);
            }
            joined = active_sessions.join_next(), if !active_sessions.is_empty() => {
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
                    ControlMessage::Offer {
                        session_id,
                        target_id,
                        ticket,
                        client_endpoint_id,
                        target_endpoint_addr,
                        ticket_public_key_pem,
                    } => {
                        anyhow::ensure!(target_id == credentials.target_id, "offer target ID differs from this agent");
                        anyhow::ensure!(target_endpoint_addr.id == endpoint.id(), "offer endpoint identity differs from this agent");
                        anyhow::ensure!(!sessions.contains_key(&session_id), "duplicate offer for session {session_id}");
                        let (peer_tx, peer_rx) = mpsc::channel(1);
                        {
                            let mut peers = pending_peers.lock().await;
                            anyhow::ensure!(peers.insert(client_endpoint_id.clone(), peer_tx).is_none(), "client EndpointId already has a pending offer");
                        }
                        let (session_tx, session_rx) = mpsc::channel(16);
                        sessions.insert(session_id, session_tx);
                        let context = context.clone();
                        let credentials = credentials.clone();
                        let outbound_tx = outbound_tx.clone();
                        let done_tx = done_tx.clone();
                        let completed_sessions = completed_sessions.clone();
                        let pending_peers = pending_peers.clone();
                        active_sessions.spawn(async move {
                            let offer = TunnelOffer {
                                session_id,
                                target_id,
                                ticket,
                                client_endpoint_id,
                                target_endpoint_addr,
                                ticket_public_key_pem,
                            };
                            let peer_endpoint_id = offer.client_endpoint_id.clone();
                            let result = handle_offer(
                                &context,
                                &credentials,
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
                            pending_peers.lock().await.remove(&peer_endpoint_id);
                            let _ = done_tx.send(session_id).await;
                        });
                        send_control_sink(&mut writer, &ControlMessage::OfferReady { session_id })
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
    credentials: &AgentCredentials,
    offer: TunnelOffer,
    mut peer_rx: mpsc::Receiver<Connection>,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let claims = decode_tunnel_ticket(
        &offer.ticket,
        &offer.ticket_public_key_pem,
        context.api.issuer(),
    )
    .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    validate_ticket(&claims, &offer, credentials)?;
    let connection = tokio::time::timeout(SESSION_SETUP_TIMEOUT, peer_rx.recv())
        .await
        .context("timed out waiting for the authenticated Iroh peer")?
        .context("agent peer listener stopped")?;
    let remote_endpoint_id = connection.remote_id().to_string();
    ensure_auth(
        remote_endpoint_id == offer.client_endpoint_id,
        "Iroh peer EndpointId differs from the ticket client EndpointId",
    )?;

    let mut stream = IrohByteStream::accept_bi(connection)
        .await
        .map_err(transport_error)?;
    let ticket_in_stream = read_ticket(&mut stream)
        .await
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    ensure_auth(
        ticket_in_stream == offer.ticket,
        "Iroh stream ticket differs from its offer",
    )?;
    outbound
        .send(ControlMessage::IrohReady {
            session_id: offer.session_id,
            client_endpoint_id: remote_endpoint_id,
        })
        .await
        .context("report authenticated Iroh peer to server")?;
    wait_activated(offer.session_id, &mut control_rx).await?;

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
) -> Result<()> {
    loop {
        match inbound
            .recv()
            .await
            .context("agent control ended before SSH activation")?
        {
            ControlMessage::Activated {
                session_id: received,
            } if received == session_id => return Ok(()),
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                if code == "authentication" || code == "authorization" {
                    bail!(AgentAuthenticationFailure(message));
                }
                bail!("server rejected SSH session before activation: {message}");
            }
            ControlMessage::Close {
                session_id: received,
                reason,
            } if received == session_id => {
                bail!("server closed SSH session before activation: {reason}");
            }
            _ => {}
        }
    }
}

async fn read_ticket(stream: &mut IrohByteStream) -> Result<String> {
    let length = stream
        .read_u32()
        .await
        .context("read ticket frame length")? as usize;
    anyhow::ensure!(
        length > 0 && length <= MAX_TICKET_FRAME,
        "ticket frame length is invalid"
    );
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .context("read ticket frame")?;
    String::from_utf8(bytes).context("ticket frame is not UTF-8")
}

fn message_session_id(message: &ControlMessage) -> Option<Uuid> {
    match message {
        ControlMessage::Activated { session_id }
        | ControlMessage::IrohReady { session_id, .. }
        | ControlMessage::OfferReady { session_id }
        | ControlMessage::Close { session_id, .. } => Some(*session_id),
        ControlMessage::Error { session_id, .. } => *session_id,
        ControlMessage::Open { .. }
        | ControlMessage::Offer { .. }
        | ControlMessage::AgentReady { .. } => None,
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
