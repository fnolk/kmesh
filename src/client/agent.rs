use std::{
    collections::HashMap,
    fs,
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::RngExt;
use sha2::Digest;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    task::JoinSet,
    time::{Instant, sleep, timeout_at},
};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{decode_tunnel_ticket, generate_target_certificate},
    protocol::{
        AgentCredentials, AgentEnrollmentRequest, ControlMessage, DirectAuthentication, PeerRole,
        QuicChallenge, RelayConnectQuery, SelectedPath, TunnelTicketClaims,
    },
    transport::{
        QuicAcceptor, QuicByteStream, QuicConfig, RelayByteStream, TransportError, UdpAttempt,
    },
};

use super::{
    AsyncReadWrite, ClientContext,
    api::{Api, ApiFailure},
    profile::{self, write_json_atomic},
};

const DIRECT_BUDGET: Duration = Duration::from_secs(2);
const CONTROL_RETRY_MAX: Duration = Duration::from_secs(30);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HANDSHAKE_FRAME: usize = 8192;

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingIdentity {
    certificate_pem: String,
    private_key_pem: String,
}

struct TunnelOffer {
    session_id: Uuid,
    target_id: Uuid,
    ticket: String,
    client_public_key: String,
    probe_token: [u8; 32],
    target_certificate_der: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
#[error("agent connection authentication failed: {0}")]
struct AgentAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("server selected relay path")]
struct RelaySelected;

pub async fn enroll(context: &ClientContext, target_id: Uuid, enrollment_code: &str) -> Result<()> {
    let credential_path = profile::agent_credentials_path(&context.config.data_dir, target_id);
    let pending_path = credential_path.with_extension("pending.json");
    let identity = if credential_path.exists() {
        let saved = profile::load_agent_credentials(&context.config.data_dir, target_id)?;
        PendingIdentity {
            certificate_pem: saved.certificate_pem,
            private_key_pem: saved.private_key_pem,
        }
    } else {
        match fs::read(&pending_path) {
            Ok(bytes) => serde_json::from_slice::<PendingIdentity>(&bytes)
                .context("read pending target identity")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let generated = generate_target_certificate(target_id)?;
                let identity = PendingIdentity {
                    certificate_pem: generated.certificate_pem,
                    private_key_pem: generated.private_key_pem,
                };
                profile::ensure_private_dir(&context.config.data_dir)?;
                write_json_atomic(&pending_path, &identity)?;
                identity
            }
            Err(error) => return Err(error).context("read pending target identity"),
        }
    };
    let response = context
        .api
        .agent_enroll(&AgentEnrollmentRequest {
            target_id,
            enrollment_token: enrollment_code.to_owned(),
            certificate_der: certificate_der(&identity.certificate_pem)?,
        })
        .await?;
    ensure_agent_auth(
        response.target_id == target_id,
        "server enrolled a different target ID",
    )?;
    profile::save_agent_credentials(
        &context.config.data_dir,
        &AgentCredentials {
            target_id,
            agent_token: response.agent_token,
            ticket_public_key_pem: response.ticket_public_key_pem,
            certificate_pem: identity.certificate_pem,
            private_key_pem: identity.private_key_pem,
        },
    )?;
    fs::remove_file(pending_path).context("remove completed enrollment identity")?;
    Ok(())
}

pub async fn run(context: &ClientContext, target_id: Uuid) -> Result<()> {
    let credentials = profile::load_agent_credentials(&context.config.data_dir, target_id)?;
    let mut active_sessions = JoinSet::new();
    let completed_sessions = Arc::new(Mutex::new(Vec::new()));
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match control_session(
            context,
            &credentials,
            &mut active_sessions,
            &completed_sessions,
        )
        .await
        {
            Ok(()) => bail!("agent control connection closed"),
            Err(error) if is_authentication_error(&error) => {
                tracing::error!(target = %target_id, error = %error, "agent credential was rejected; existing SSH sessions will finish");
                while let Some(result) = active_sessions.join_next().await {
                    if let Err(error) = result {
                        tracing::warn!(target = %target_id, error = %error, "active SSH session ended");
                    }
                }
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(target = %target_id, error = %error, retry_seconds = retry_delay.as_secs(), "agent control connection lost; existing SSH sessions remain active");
                sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(CONTROL_RETRY_MAX);
            }
        }
    }
}

async fn control_session(
    context: &ClientContext,
    credentials: &AgentCredentials,
    active_sessions: &mut JoinSet<()>,
    completed_sessions: &Arc<Mutex<Vec<Uuid>>>,
) -> Result<()> {
    let ws = tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        context.api.agent_control(&credentials.agent_token),
    )
    .await
    .context("agent control connection timed out")??;
    let (mut writer, mut reader) = ws.split();
    let completed = {
        let mut completed = completed_sessions
            .lock()
            .expect("completed session lock poisoned");
        std::mem::take(&mut *completed)
    };
    for session_id in completed {
        let message = serde_json::to_string(&ControlMessage::Cancel {
            session_id,
            reason: "session_finished_while_control_was_offline".to_owned(),
        })?;
        writer
            .send(Message::Text(message.into()))
            .await
            .context("report completed SSH session")?;
    }
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<ControlMessage>(64);
    let (done_tx, mut done_rx) = mpsc::channel::<Uuid>(16);
    let mut sessions: HashMap<Uuid, mpsc::Sender<ControlMessage>> = HashMap::new();
    loop {
        tokio::select! {
            Some(message) = outbound_rx.recv() => {
                let text = serde_json::to_string(&message).context("encode agent control message")?;
                writer.send(Message::Text(text.into())).await.context("send agent control message")?;
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
                let message = Api::control_message(incoming)?;
                match message {
                    offer @ ControlMessage::Offer { session_id, .. } => {
                        anyhow::ensure!(!sessions.contains_key(&session_id), "duplicate offer for session {session_id}");
                        let (session_tx, session_rx) = mpsc::channel(16);
                        sessions.insert(session_id, session_tx);
                        let context = context.clone();
                        let credentials = credentials.clone();
                        let outbound_tx = outbound_tx.clone();
                        let done_tx = done_tx.clone();
                        let completed_sessions = completed_sessions.clone();
                        active_sessions.spawn(async move {
                            if let Err(error) = handle_offer(&context, &credentials, offer, session_rx, outbound_tx.clone(), completed_sessions.clone()).await {
                                let code = if is_authentication_error(&error) { "authentication" } else { "network" };
                                tracing::warn!(session = %session_id, error = %error, "target tunnel setup failed");
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
                        return Err(anyhow!(AgentAuthenticationFailure(format!("server rejected agent control: {message}"))));
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
    offer: ControlMessage,
    mut inbound: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
    completed_sessions: Arc<Mutex<Vec<Uuid>>>,
) -> Result<()> {
    let ControlMessage::Offer {
        session_id,
        target_id,
        ticket,
        client_public_key,
        probe_token,
        target_certificate_der,
        ticket_public_key_pem,
    } = offer
    else {
        bail!("expected an offer")
    };
    ensure_agent_auth(
        target_id == credentials.target_id,
        "offer target does not match enrolled identity",
    )?;
    ensure_agent_auth(
        ticket_public_key_pem == credentials.ticket_public_key_pem,
        "server ticket key differs from enrolled key",
    )?;
    ensure_agent_auth(
        certificate_fingerprint(&target_certificate_der)
            == certificate_fingerprint(&certificate_der(&credentials.certificate_pem)?),
        "offer certificate differs from enrolled target certificate",
    )?;
    let claims = decode_tunnel_ticket(
        &ticket,
        &credentials.ticket_public_key_pem,
        context.api.issuer(),
    )
    .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    let probe_token = decode_probe_token(&probe_token)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    let offer = TunnelOffer {
        session_id,
        target_id,
        ticket,
        client_public_key,
        probe_token,
        target_certificate_der,
    };
    verify_ticket_binding(&claims, &offer)?;
    let deadline = Instant::now() + DIRECT_BUDGET;
    let direct = direct_accept(
        context,
        credentials,
        &offer,
        deadline,
        &mut inbound,
        &outbound,
    )
    .await;
    let mut stream: Box<dyn AsyncReadWrite + Send + Unpin> = match direct {
        Ok(stream) => Box::new(stream),
        Err(error) if is_authentication_error(&error) => return Err(error),
        Err(error) if is_relay_selected(&error) => {
            relay_stream(
                context,
                credentials,
                offer.session_id,
                &mut inbound,
                &outbound,
            )
            .await?
        }
        Err(error) => {
            tracing::debug!(session = %offer.session_id, error = %error, "direct path did not become available");
            await_relay_selection(offer.session_id, &mut inbound).await?;
            relay_stream(
                context,
                credentials,
                offer.session_id,
                &mut inbound,
                &outbound,
            )
            .await?
        }
    };
    let result = copy_ssh(context, &mut stream).await;
    if outbound
        .send(ControlMessage::Cancel {
            session_id: offer.session_id,
            reason: "session_finished".to_owned(),
        })
        .await
        .is_err()
    {
        remember_completed(&completed_sessions, offer.session_id);
        tracing::debug!(session = %offer.session_id, "control is offline; will report session completion after reconnect");
    }
    result
}

async fn relay_stream(
    context: &ClientContext,
    credentials: &AgentCredentials,
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
    outbound: &mpsc::Sender<ControlMessage>,
) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>> {
    let ws = context
        .api
        .relay(
            &credentials.agent_token,
            &RelayConnectQuery {
                session_id,
                peer: PeerRole::Target,
            },
        )
        .await?;
    send_control(
        outbound,
        ControlMessage::Activate {
            session_id,
            path: SelectedPath::Relay,
        },
    )
    .await?;
    wait_activated(session_id, SelectedPath::Relay, inbound).await?;
    Ok(Box::new(RelayByteStream::from_ws(ws)))
}

async fn direct_accept(
    context: &ClientContext,
    credentials: &AgentCredentials,
    offer: &TunnelOffer,
    deadline: Instant,
    inbound: &mut mpsc::Receiver<ControlMessage>,
    outbound: &mpsc::Sender<ControlMessage>,
) -> Result<QuicByteStream> {
    let started = Instant::now();
    let mut stun = context.config.stun.clone();
    if stun.servers.is_empty() {
        stun.servers
            .push(stun_endpoint(&context.config.server_url)?);
    }
    let mut attempt = timeout_at(deadline, UdpAttempt::bind(stun))
        .await
        .context("direct UDP bind timed out")??;
    let candidates = timeout_at(deadline, attempt.gather())
        .await
        .context("STUN gather timed out")??;
    tracing::debug!(session = %offer.session_id, elapsed_ms = started.elapsed().as_millis(), "target STUN gather complete");
    send_control(
        outbound,
        ControlMessage::Candidates {
            session_id: offer.session_id,
            candidates,
        },
    )
    .await?;
    let remote = receive_candidates(offer.session_id, inbound, deadline).await?;
    tracing::debug!(session = %offer.session_id, elapsed_ms = started.elapsed().as_millis(), "target peer candidates received");
    let probe_result = timeout_at(
        deadline,
        attempt.probe(
            offer.session_id,
            offer.probe_token,
            &remote,
            remaining(deadline)?,
        ),
    )
    .await
    .context("UDP probe timed out")??;
    let peer = probe_result.peer_addr;
    tracing::debug!(session = %offer.session_id, elapsed_ms = started.elapsed().as_millis(), "target UDP probe complete");
    send_control(
        outbound,
        ControlMessage::ProbeSeen {
            session_id: offer.session_id,
            peer: PeerRole::Target,
            candidate: peer,
        },
    )
    .await?;
    let acceptor = attempt.into_quic_server(
        credentials.target_id,
        &credentials.certificate_pem,
        &credentials.private_key_pem,
        QuicConfig::default(),
    )?;
    send_control(
        outbound,
        ControlMessage::QuicReady {
            session_id: offer.session_id,
        },
    )
    .await?;
    tracing::debug!(session = %offer.session_id, elapsed_ms = started.elapsed().as_millis(), "target QUIC acceptor ready");
    let (mut stream, client_quic_ready) =
        accept_with_relay(&acceptor, offer.session_id, inbound, deadline).await?;
    tracing::debug!(session = %offer.session_id, elapsed_ms = started.elapsed().as_millis(), "target QUIC stream accepted");
    timeout_at(
        deadline,
        authenticate_quic(
            &mut stream,
            offer,
            credentials,
            context.api.issuer(),
            remaining(deadline)?,
        ),
    )
    .await
    .context("QUIC authentication timed out")??;
    tracing::debug!(session = %offer.session_id, elapsed_ms = started.elapsed().as_millis(), "target client proof verified");
    if !client_quic_ready {
        wait_client_quic_ready(offer.session_id, inbound, deadline).await?;
    }
    tracing::debug!(session = %offer.session_id, elapsed_ms = started.elapsed().as_millis(), "client QUIC readiness received");
    send_control(
        outbound,
        ControlMessage::Activate {
            session_id: offer.session_id,
            path: SelectedPath::Quic,
        },
    )
    .await?;
    timeout_at(
        deadline,
        wait_activated(offer.session_id, SelectedPath::Quic, inbound),
    )
    .await
    .context("server path activation timed out")??;
    Ok(stream)
}

async fn receive_candidates(
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
    deadline: Instant,
) -> Result<Vec<SocketAddr>> {
    loop {
        match receive_until(inbound, deadline).await? {
            ControlMessage::Candidates {
                session_id: received,
                candidates,
            } if received == session_id => return Ok(candidates),
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id => return Err(RelaySelected.into()),
            message => route_unexpected(session_id, message)?,
        }
    }
}

async fn accept_with_relay(
    acceptor: &QuicAcceptor,
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
    deadline: Instant,
) -> Result<(QuicByteStream, bool)> {
    let mut client_quic_ready = false;
    let accepting = acceptor.accept();
    tokio::pin!(accepting);
    loop {
        tokio::select! {
            result = timeout_at(deadline, &mut accepting) => {
                let stream = result.context("QUIC accept timed out")?.map_err(anyhow::Error::new)?;
                return Ok((stream, client_quic_ready));
            }
            message = receive_until(inbound, deadline) => {
                match message? {
                    ControlMessage::SelectRelay { session_id: received } if received == session_id => return Err(RelaySelected.into()),
                    ControlMessage::QuicReady { session_id: received } if received == session_id => client_quic_ready = true,
                    message => route_unexpected(session_id, message)?,
                }
            }
        }
    }
}

async fn wait_client_quic_ready(
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
    deadline: Instant,
) -> Result<()> {
    loop {
        match receive_until(inbound, deadline).await? {
            ControlMessage::QuicReady {
                session_id: received,
            } if received == session_id => return Ok(()),
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id => return Err(RelaySelected.into()),
            message => route_unexpected(session_id, message)?,
        }
    }
}

async fn authenticate_quic(
    stream: &mut QuicByteStream,
    offer: &TunnelOffer,
    credentials: &AgentCredentials,
    expected_issuer: &str,
    budget: Duration,
) -> Result<()> {
    let mut nonce_bytes = [0_u8; 32];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    timeout_write_frame(
        stream,
        &QuicChallenge {
            nonce: nonce.clone(),
        },
        budget,
    )
    .await?;
    let auth: DirectAuthentication = timeout_read_frame(stream, budget).await?;
    ensure_agent_auth(
        auth.ticket == offer.ticket,
        "QUIC proof carries a different ticket",
    )?;
    let verified = decode_tunnel_ticket(
        &auth.ticket,
        &credentials.ticket_public_key_pem,
        expected_issuer,
    )
    .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    verify_ticket_binding(&verified, offer)?;
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(&offer.client_public_key)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        anyhow!(AgentAuthenticationFailure(
            "client Ed25519 key must contain 32 bytes".to_owned()
        ))
    })?;
    let public_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(auth.signature)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    public_key
        .verify_strict(&quic_auth_message(&offer.ticket, &nonce), &signature)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))
}

pub(crate) fn quic_auth_message(ticket: &str, nonce: &str) -> Vec<u8> {
    format!("kmesh-quic-auth\0{ticket}\0{nonce}").into_bytes()
}

fn verify_ticket_binding(claims: &TunnelTicketClaims, offer: &TunnelOffer) -> Result<()> {
    ensure_agent_auth(
        claims.session_id == offer.session_id,
        "ticket session ID mismatch",
    )?;
    ensure_agent_auth(
        claims.target_id == offer.target_id,
        "ticket target ID mismatch",
    )?;
    ensure_agent_auth(
        claims.client_public_key == offer.client_public_key,
        "ticket client key mismatch",
    )?;
    let fingerprint = certificate_fingerprint(&offer.target_certificate_der);
    ensure_agent_auth(
        claims.target_certificate_fingerprint == fingerprint,
        "ticket target certificate fingerprint mismatch",
    )
}

async fn await_relay_selection(
    session_id: Uuid,
    inbound: &mut mpsc::Receiver<ControlMessage>,
) -> Result<()> {
    loop {
        match tokio::time::timeout(Duration::from_secs(30), inbound.recv())
            .await
            .context("waiting for relay selection timed out")?
            .context("agent control ended before relay selection")?
        {
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id => return Ok(()),
            ControlMessage::Cancel {
                session_id: received,
                reason,
            } if received == session_id => bail!("connection canceled: {reason}"),
            message => route_unexpected(session_id, message)?,
        }
    }
}

async fn wait_activated(
    session_id: Uuid,
    expected_path: SelectedPath,
    inbound: &mut mpsc::Receiver<ControlMessage>,
) -> Result<()> {
    loop {
        match inbound
            .recv()
            .await
            .context("agent control ended before path activation")?
        {
            ControlMessage::Activated {
                session_id: received,
                path,
            } if received == session_id => {
                ensure_agent_auth(
                    path == expected_path,
                    "server activated a different data path",
                )?;
                return Ok(());
            }
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id && expected_path == SelectedPath::Quic => {
                return Err(RelaySelected.into());
            }
            message => route_unexpected(session_id, message)?,
        }
    }
}

async fn copy_ssh<S>(context: &ClientContext, stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut socket = tokio::time::timeout(
        Duration::from_secs(context.config.ssh.connect_timeout_secs),
        TcpStream::connect(context.config.ssh.address),
    )
    .await
    .context("local sshd connection timed out")?
    .context("connect to local sshd")?;
    socket
        .set_nodelay(true)
        .context("enable TCP_NODELAY for sshd")?;
    tokio::io::copy_bidirectional(stream, &mut socket)
        .await
        .context("forward SSH byte stream")?;
    Ok(())
}

async fn send_control(
    sender: &mpsc::Sender<ControlMessage>,
    message: ControlMessage,
) -> Result<()> {
    sender
        .send(message)
        .await
        .context("agent control writer stopped")
}

async fn receive_until(
    receiver: &mut mpsc::Receiver<ControlMessage>,
    deadline: Instant,
) -> Result<ControlMessage> {
    timeout_at(deadline, receiver.recv())
        .await
        .context("direct path deadline expired")?
        .context("agent control stopped")
}

fn route_unexpected(session_id: Uuid, message: ControlMessage) -> Result<()> {
    if let ControlMessage::Error {
        session_id: Some(received),
        code,
        message,
    } = message
        && received == session_id
    {
        if code == "authentication" || code == "authorization" {
            return Err(anyhow!(AgentAuthenticationFailure(format!(
                "server rejected connection ({code}): {message}"
            ))));
        }
        bail!("server rejected connection ({code}): {message}");
    }
    Ok(())
}

fn message_session_id(message: &ControlMessage) -> Option<Uuid> {
    match message {
        ControlMessage::Open { session_id, .. }
        | ControlMessage::Offer { session_id, .. }
        | ControlMessage::Candidates { session_id, .. }
        | ControlMessage::ProbeSeen { session_id, .. }
        | ControlMessage::QuicReady { session_id }
        | ControlMessage::SelectRelay { session_id }
        | ControlMessage::Activate { session_id, .. }
        | ControlMessage::Activated { session_id, .. }
        | ControlMessage::Cancel { session_id, .. } => Some(*session_id),
        ControlMessage::Error { session_id, .. } => *session_id,
    }
}

fn decode_probe_token(token: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .context("decode UDP probe token")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("UDP probe token must contain 32 bytes"))
}

fn stun_endpoint(server_url: &str) -> Result<String> {
    let url = reqwest::Url::parse(server_url).context("parse server URL for STUN endpoint")?;
    let host = url.host_str().context("server URL has no host")?;
    if host.starts_with('[') || !host.contains(':') {
        Ok(format!("{host}:3478"))
    } else {
        Ok(format!("[{host}]:3478"))
    }
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .context("direct connection budget expired")
}

async fn timeout_write_frame<W, T>(stream: &mut W, message: &T, timeout: Duration) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let payload = serde_json::to_vec(message).context("encode QUIC handshake frame")?;
    anyhow::ensure!(
        payload.len() <= MAX_HANDSHAKE_FRAME,
        "QUIC handshake frame is too large"
    );
    tokio::time::timeout(timeout, async {
        stream.write_u32(payload.len() as u32).await?;
        stream.write_all(&payload).await?;
        stream.flush().await
    })
    .await
    .context("write QUIC handshake frame timed out")?
    .context("write QUIC handshake frame")
}

async fn timeout_read_frame<R, T>(stream: &mut R, timeout: Duration) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> serde::Deserialize<'de>,
{
    tokio::time::timeout(timeout, async {
        let length = stream.read_u32().await? as usize;
        anyhow::ensure!(
            length <= MAX_HANDSHAKE_FRAME,
            "QUIC handshake frame is too large"
        );
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        serde_json::from_slice(&payload).context("decode QUIC handshake frame")
    })
    .await
    .context("read QUIC handshake frame timed out")?
}

fn is_authentication_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<AgentAuthenticationFailure>().is_some()
            || cause
                .downcast_ref::<ApiFailure>()
                .is_some_and(|failure| matches!(failure, ApiFailure::Authentication(_)))
            || cause
                .downcast_ref::<TransportError>()
                .is_some_and(|transport| {
                    matches!(
                        transport,
                        TransportError::Authentication(_) | TransportError::ProtocolViolation(_)
                    )
                })
    })
}

fn is_relay_selected(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<RelaySelected>().is_some())
}

fn remember_completed(completed_sessions: &Arc<Mutex<Vec<Uuid>>>, session_id: Uuid) {
    let mut completed = completed_sessions
        .lock()
        .expect("completed session lock poisoned");
    if !completed.contains(&session_id) {
        completed.push(session_id);
    }
}

fn ensure_agent_auth(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(AgentAuthenticationFailure(message.to_owned())))
    }
}

fn certificate_fingerprint(certificate_der: &[u8]) -> String {
    format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(certificate_der))
    )
}

fn certificate_der(certificate_pem: &str) -> Result<Vec<u8>> {
    rustls_pemfile::certs(&mut Cursor::new(certificate_pem.as_bytes()))
        .next()
        .context("target certificate PEM is empty")?
        .context("parse target certificate PEM")
        .map(|certificate| certificate.as_ref().to_vec())
}
