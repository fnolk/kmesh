use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use tokio::{
    io::AsyncWriteExt,
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
        IrohByteStream, IrohEndpointOptions, RelayChoice, TransportError, connect_peer,
        create_endpoint, validate_endpoint_addr, wait_endpoint_ready,
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
    client_endpoint_addr: EndpointAddr,
    ticket_public_key_pem: String,
    relay_mode: RelayMode,
}

type EndpointMap = Arc<Mutex<HashMap<RelayMode, Endpoint>>>;

struct AgentRuntime {
    endpoint_secret_key: SecretKey,
    transport_info: TransportInfo,
    endpoints: EndpointMap,
    active_sessions: JoinSet<()>,
    completed_sessions: Arc<StdMutex<Vec<Uuid>>>,
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
    let mut runtime = AgentRuntime {
        endpoint_secret_key: decode_secret_key(&credentials.endpoint_secret_key)?,
        transport_info: context.api.transport_info().await?,
        endpoints: Arc::new(Mutex::new(HashMap::new())),
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

async fn prepare_endpoint(
    context: &ClientContext,
    endpoint_secret_key: &SecretKey,
    transport_info: &TransportInfo,
    relay_mode: RelayMode,
    endpoints: &EndpointMap,
) -> std::result::Result<EndpointAddr, TransportError> {
    let endpoint = {
        let mut endpoints = endpoints.lock().await;
        if let Some(endpoint) = endpoints.get(&relay_mode).cloned() {
            endpoint
        } else {
            let options = endpoint_options(context, transport_info, relay_mode)
                .map_err(|error| TransportError::Configuration(error.to_string()))?;
            let endpoint = create_endpoint(endpoint_secret_key.clone(), false, options).await?;
            endpoints.insert(relay_mode, endpoint.clone());
            endpoint
        }
    };
    wait_endpoint_ready(&endpoint, RELAY_ENDPOINT_TIMEOUT).await?;
    Ok(endpoint.addr())
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
                        ).await {
                            Ok(endpoint_addr) => {
                                tracing::debug!(
                                    session = %session_id,
                                    relay_mode = ?relay_mode,
                                    target_endpoint_id = %endpoint_addr.id,
                                    target_ip_addrs = ?endpoint_addr.ip_addrs().copied().collect::<Vec<_>>(),
                                    "prepared target Iroh dial endpoint"
                                );
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
                    ControlMessage::DialOffer {
                        session_id,
                        target_id,
                        ticket,
                        client_endpoint_id,
                        client_endpoint_addr,
                        ticket_public_key_pem,
                        relay_mode,
                    } => {
                        let offer = TunnelOffer {
                            session_id,
                            target_id,
                            ticket,
                            client_endpoint_id,
                            client_endpoint_addr,
                            ticket_public_key_pem,
                            relay_mode,
                        };
                        let claims = match decode_tunnel_ticket(
                            &offer.ticket,
                            &offer.ticket_public_key_pem,
                            context.api.issuer(),
                        ) {
                            Ok(claims) => claims,
                            Err(error) => {
                                outbound_tx.send(ControlMessage::Error {
                                    session_id: Some(session_id),
                                    code: "authentication".to_owned(),
                                    message: error.to_string(),
                                }).await.context("report invalid signed tunnel offer")?;
                                continue;
                            }
                        };
                        let endpoint = runtime.endpoints.lock().await.get(&relay_mode).cloned()
                            .context("offer relay endpoint has not been prepared")?;
                        if let Err(error) = validate_ticket(&claims, &offer, credentials, endpoint.id()) {
                            outbound_tx.send(ControlMessage::Error {
                                session_id: Some(session_id),
                                code: "authentication".to_owned(),
                                message: error.to_string(),
                            }).await.context("report invalid signed tunnel offer")?;
                            continue;
                        }
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
                        if offer.client_endpoint_addr.id.to_string() != offer.client_endpoint_id
                            || offer.client_endpoint_addr.ip_addrs().count() > 32
                            || offer.client_endpoint_addr.relay_urls().next().is_none()
                        {
                            outbound_tx.send(ControlMessage::Error {
                                session_id: Some(session_id),
                                code: "authentication".to_owned(),
                                message: "client EndpointAddr differs from the ticket identity or exceeds limits".to_owned(),
                            }).await.context("reject invalid client EndpointAddr")?;
                            continue;
                        }
                        if let Err(error) = validate_endpoint_addr(
                            &offer.client_endpoint_addr,
                            &relay_choice,
                        ) {
                            outbound_tx.send(ControlMessage::Error {
                                session_id: Some(session_id),
                                code: "authentication".to_owned(),
                                message: error.to_string(),
                            }).await.context("reject untrusted client relay address")?;
                            continue;
                        }
                        anyhow::ensure!(!sessions.contains_key(&session_id), "duplicate offer for session {session_id}");
                        let (session_tx, session_rx) = mpsc::channel(16);
                        sessions.insert(session_id, session_tx);
                        let context = context.clone();
                        let relay_choice = relay_choice.clone();
                        let outbound_tx = outbound_tx.clone();
                        let done_tx = done_tx.clone();
                        let completed_sessions = runtime.completed_sessions.clone();
                        runtime.active_sessions.spawn(async move {
                            let result = handle_dial_offer(
                                &context,
                                offer,
                                endpoint,
                                relay_choice,
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
                            let _ = done_tx.send(session_id).await;
                        });
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

async fn handle_dial_offer(
    context: &ClientContext,
    offer: TunnelOffer,
    endpoint: Endpoint,
    relay_choice: RelayChoice,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let connection = tokio::time::timeout(SESSION_SETUP_TIMEOUT, async {
        tokio::select! {
            biased;
            control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
                control.map(|()| None)
            },
            connection = connect_peer(&endpoint, offer.client_endpoint_addr.clone(), &relay_choice) => {
                connection.map(Some).map_err(transport_error)
            },
        }
    })
        .await
        .context("timed out connecting to the client Iroh endpoint")?
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
        result = IrohByteStream::open_bi(connection) => result.map_err(transport_error)?,
    };
    tokio::select! {
        biased;
        control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
            control?;
            return Ok(());
        },
        result = write_ticket(&mut stream, &offer.ticket) => result.context("send signed tunnel ticket to client")?,
    }
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

async fn write_ticket(stream: &mut IrohByteStream, ticket: &str) -> Result<()> {
    let bytes = ticket.as_bytes();
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_TICKET_FRAME,
        "signed ticket exceeds the handshake frame limit"
    );
    stream
        .write_u32(bytes.len() as u32)
        .await
        .context("write ticket frame length")?;
    stream
        .write_all(bytes)
        .await
        .context("write ticket frame")?;
    stream.flush().await.context("flush ticket frame")
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
    target_endpoint_id: iroh::EndpointId,
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
        claims.target_endpoint_id == target_endpoint_id.to_string(),
        "ticket target EndpointId mismatch",
    )?;
    ensure_auth(
        offer.client_endpoint_addr.id.to_string() == offer.client_endpoint_id,
        "client EndpointAddr differs from the ticket client EndpointId",
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

fn message_session_id(message: &ControlMessage) -> Option<Uuid> {
    match message {
        ControlMessage::Activated { session_id }
        | ControlMessage::IrohReady { session_id, .. }
        | ControlMessage::DialOffer { session_id, .. }
        | ControlMessage::Prepare { session_id, .. }
        | ControlMessage::Close { session_id, .. } => Some(*session_id),
        ControlMessage::Error { session_id, .. } => *session_id,
        ControlMessage::Open { .. }
        | ControlMessage::ClientOffer { .. }
        | ControlMessage::ClientReady { .. }
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
    use crate::{client::proxy::read_ticket, transport::accept_peer};
    use iroh::{Endpoint, endpoint::presets};

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
            relay_mode: RelayMode::PublicDefault,
        }
    }

    async fn await_offer(task: tokio::task::JoinHandle<Result<()>>) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("agent dial did not finish promptly")
            .expect("agent dial task panicked")
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
    async fn target_dials_the_client_and_reports_only_after_ticket_write() {
        let context = context("https://kmesh.test:9443").await;
        let (client, target) = local_endpoints().await;
        let offer = offer(&client);
        let session_id = offer.session_id;
        let client_endpoint_id = client.id().to_string();
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
                target,
                RelayChoice::PublicDefault,
                control_rx,
                outbound,
            )
            .await
        });

        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), outbound_rx.recv())
                .await
                .expect("target did not report Iroh readiness")
            .expect("target control channel closed"),
            ControlMessage::IrohReady { session_id: received, client_endpoint_id: reported_id, relay_mode: RelayMode::PublicDefault }
                if received == session_id && reported_id == client_endpoint_id
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
                target,
                RelayChoice::PublicDefault,
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
                target,
                RelayChoice::PublicDefault,
                control_rx,
                outbound,
            )
            .await
        });
        drop(control_tx);
        assert!(await_offer(task).await.is_ok());
    }
}
