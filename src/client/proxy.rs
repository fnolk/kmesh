use std::{io, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::StreamExt;
use rand::rng;
use sha2::Digest;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{
        ControlMessage, DirectAuthentication, PeerRole, QuicChallenge, RelayConnectQuery,
        SelectedPath, TunnelTicketClaims,
    },
    transport::{QuicByteStream, QuicConfig, RelayByteStream, TransportError, UdpAttempt},
};

use super::{
    ClientContext,
    agent::quic_auth_message,
    api::{Api, WsStream},
    auth,
};

const DIRECT_BUDGET: Duration = Duration::from_secs(2);
const RELAY_SELECTION_TIMEOUT: Duration = Duration::from_secs(15);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HANDSHAKE_FRAME: usize = 8192;

#[derive(Debug)]
enum DirectFailure {
    Network(String),
    Fatal(anyhow::Error),
    RelaySelected,
}

pub async fn run(context: &ClientContext, target_id: Uuid) -> Result<()> {
    let access_token = auth::valid_access_token(context).await?;
    let session_id = Uuid::new_v4();
    let ephemeral = SigningKey::generate(&mut rng());
    let client_public_key = URL_SAFE_NO_PAD.encode(ephemeral.verifying_key().to_bytes());
    let mut control = context.api.connect_control(&access_token).await?;
    Api::send_control(
        &mut control,
        &ControlMessage::Open {
            session_id,
            target_id,
            client_public_key: client_public_key.clone(),
        },
    )
    .await?;
    let offer = tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        next_offer(&mut control, session_id, target_id, context.api.issuer()),
    )
    .await
    .context("waiting for connection offer timed out")??;
    let deadline = Instant::now() + DIRECT_BUDGET;
    let direct = timeout_at(
        deadline,
        direct_attempt(
            context,
            &mut control,
            &offer,
            session_id,
            &client_public_key,
            &ephemeral,
            deadline,
        ),
    )
    .await;
    match direct {
        Ok(Ok(mut stream)) => {
            eprintln!("连接路径：P2P / QUIC");
            copy_stdio(&mut stream).await
        }
        Ok(Err(DirectFailure::Fatal(error))) => Err(error),
        Ok(Err(DirectFailure::RelaySelected)) => {
            relay(context, &mut control, &access_token, session_id).await
        }
        Ok(Err(DirectFailure::Network(reason))) => {
            tracing::debug!(session = %session_id, reason = %reason, "direct path unavailable; requesting relay");
            select_relay(context, &mut control, &access_token, session_id).await
        }
        Err(_) => {
            tracing::debug!(session = %session_id, "direct path deadline reached; requesting relay");
            select_relay(context, &mut control, &access_token, session_id).await
        }
    }
}

struct OfferData {
    target_id: Uuid,
    ticket: String,
    client_public_key: String,
    probe_token: [u8; 32],
    target_certificate_der: Vec<u8>,
    claims: TunnelTicketClaims,
}

async fn next_offer(
    control: &mut WsStream,
    session_id: Uuid,
    requested_target_id: Uuid,
    expected_issuer: &str,
) -> Result<OfferData> {
    loop {
        let message = control
            .next()
            .await
            .context("control WebSocket ended before offer")?
            .context("read control WebSocket")?;
        if matches!(message, Message::Ping(_) | Message::Pong(_)) {
            continue;
        }
        match Api::control_message(message)? {
            ControlMessage::Offer {
                session_id: received,
                target_id,
                ticket,
                client_public_key,
                probe_token,
                target_certificate_der,
                ticket_public_key_pem,
            } if received == session_id => {
                let claims = decode_tunnel_ticket(&ticket, &ticket_public_key_pem, expected_issuer)
                    .map_err(|error| anyhow!(DirectAuthenticationFailure(error.to_string())))?;
                let decoded_probe = URL_SAFE_NO_PAD
                    .decode(&probe_token)
                    .context("decode UDP probe token")
                    .map_err(as_auth_failure)?;
                let probe_token: [u8; 32] = decoded_probe.try_into().map_err(|_| {
                    anyhow!(DirectAuthenticationFailure(
                        "UDP probe token must contain 32 bytes".to_owned()
                    ))
                })?;
                let data = OfferData {
                    target_id,
                    ticket,
                    client_public_key,
                    probe_token,
                    target_certificate_der,
                    claims,
                };
                validate_offer(&data, session_id)?;
                ensure_auth(
                    data.target_id == requested_target_id,
                    "offer target ID differs from requested target",
                )?;
                return Ok(data);
            }
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                if code == "authentication" || code == "authorization" {
                    bail!("server rejected SSH access: {message}");
                }
                bail!("server could not prepare SSH access: {message}");
            }
            message => tracing::debug!(?message, "ignoring control message before offer"),
        }
    }
}

fn validate_offer(offer: &OfferData, session_id: Uuid) -> Result<()> {
    ensure_auth(
        offer.claims.session_id == session_id,
        "ticket session ID mismatch",
    )?;
    ensure_auth(
        offer.claims.target_id == offer.target_id,
        "ticket target ID mismatch",
    )?;
    ensure_auth(
        offer.claims.client_public_key == offer.client_public_key,
        "ticket client key mismatch",
    )?;
    ensure_auth(
        offer.claims.aud == TUNNEL_TICKET_AUDIENCE,
        "ticket audience mismatch",
    )?;
    let fingerprint = fingerprint(&offer.target_certificate_der);
    ensure_auth(
        offer.claims.target_certificate_fingerprint == fingerprint,
        "ticket target certificate fingerprint mismatch",
    )
}

async fn direct_attempt(
    context: &ClientContext,
    control: &mut WsStream,
    offer: &OfferData,
    session_id: Uuid,
    client_public_key: &str,
    ephemeral: &SigningKey,
    deadline: Instant,
) -> std::result::Result<QuicByteStream, DirectFailure> {
    let started = Instant::now();
    if offer.client_public_key != client_public_key {
        return Err(DirectFailure::Fatal(anyhow!(DirectAuthenticationFailure(
            "offer client key differs from this connection".to_owned(),
        ))));
    }
    let mut stun = context.config.stun.clone();
    if stun.servers.is_empty() {
        stun.servers
            .push(stun_endpoint(&context.config.server_url).map_err(DirectFailure::Fatal)?);
    }
    let mut attempt = timeout_at(deadline, UdpAttempt::bind(stun))
        .await
        .map_err(|_| DirectFailure::Network("UDP bind timed out".to_owned()))?
        .map_err(classify_transport)?;
    let candidates = timeout_at(deadline, attempt.gather())
        .await
        .map_err(|_| DirectFailure::Network("STUN gather timed out".to_owned()))?
        .map_err(classify_transport)?;
    tracing::debug!(session = %session_id, elapsed_ms = started.elapsed().as_millis(), "client STUN gather complete");
    Api::send_control(
        control,
        &ControlMessage::Candidates {
            session_id,
            candidates,
        },
    )
    .await
    .map_err(DirectFailure::Fatal)?;
    let remote = receive_candidates(control, session_id, deadline).await?;
    tracing::debug!(session = %session_id, elapsed_ms = started.elapsed().as_millis(), "client peer candidates received");
    let probe_result = timeout_at(
        deadline,
        attempt.probe(
            session_id,
            offer.probe_token,
            &remote,
            remaining(deadline).map_err(DirectFailure::Fatal)?,
        ),
    )
    .await
    .map_err(|_| DirectFailure::Network("UDP hole-punch probe timed out".to_owned()))?
    .map_err(classify_transport)?;
    let peer = probe_result.peer_addr;
    tracing::debug!(session = %session_id, elapsed_ms = started.elapsed().as_millis(), "client UDP probe complete");
    Api::send_control(
        control,
        &ControlMessage::ProbeSeen {
            session_id,
            peer: PeerRole::Client,
            candidate: peer,
        },
    )
    .await
    .map_err(DirectFailure::Fatal)?;
    wait_quic_ready(control, session_id, deadline).await?;
    tracing::debug!(session = %session_id, elapsed_ms = started.elapsed().as_millis(), "target QUIC acceptor ready");
    let mut stream = timeout_at(
        deadline,
        attempt.into_quic_client(
            offer.target_id,
            peer,
            offer.target_certificate_der.clone(),
            &offer.claims.target_certificate_fingerprint,
            QuicConfig::default(),
        ),
    )
    .await
    .map_err(|_| DirectFailure::Network("QUIC connect timed out".to_owned()))?
    .map_err(classify_transport)?;
    tracing::debug!(session = %session_id, elapsed_ms = started.elapsed().as_millis(), "client QUIC stream established");
    Api::send_control(control, &ControlMessage::QuicReady { session_id })
        .await
        .map_err(DirectFailure::Fatal)?;

    let challenge: QuicChallenge = timeout_read_frame(
        &mut stream,
        remaining(deadline).map_err(DirectFailure::Fatal)?,
    )
    .await
    .map_err(classify_anyhow)?;
    tracing::debug!(session = %session_id, elapsed_ms = started.elapsed().as_millis(), "client QUIC proof sent");
    let nonce = URL_SAFE_NO_PAD
        .decode(&challenge.nonce)
        .context("decode QUIC challenge nonce")
        .map_err(as_auth_failure)
        .map_err(DirectFailure::Fatal)?;
    if nonce.len() != 32 {
        return Err(DirectFailure::Fatal(anyhow!(DirectAuthenticationFailure(
            "QUIC challenge nonce must contain 32 bytes".to_owned(),
        ))));
    }
    let signature = ephemeral.sign(&quic_auth_message(&offer.ticket, &challenge.nonce));
    let authentication = DirectAuthentication {
        ticket: offer.ticket.clone(),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    timeout_write_frame(
        &mut stream,
        &authentication,
        remaining(deadline).map_err(DirectFailure::Fatal)?,
    )
    .await
    .map_err(classify_anyhow)?;
    wait_activated(control, session_id, SelectedPath::Quic, deadline).await?;
    tracing::debug!(session = %session_id, elapsed_ms = started.elapsed().as_millis(), "direct path activated");
    Ok(stream)
}

async fn select_relay(
    context: &ClientContext,
    control: &mut WsStream,
    access_token: &str,
    session_id: Uuid,
) -> Result<()> {
    Api::send_control(control, &ControlMessage::SelectRelay { session_id }).await?;
    loop {
        match tokio::time::timeout(RELAY_SELECTION_TIMEOUT, next_control(control))
            .await
            .context("server relay selection timed out")??
        {
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id => break,
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                bail!("server rejected relay selection ({code}): {message}");
            }
            message => tracing::debug!(?message, "waiting for relay selection"),
        }
    }
    relay(context, control, access_token, session_id).await
}

async fn relay(
    context: &ClientContext,
    control: &mut WsStream,
    access_token: &str,
    session_id: Uuid,
) -> Result<()> {
    let ws = context
        .api
        .relay(
            access_token,
            &RelayConnectQuery {
                session_id,
                peer: PeerRole::Client,
            },
        )
        .await?;
    let mut stream = RelayByteStream::from_ws(ws);
    wait_activated(
        control,
        session_id,
        SelectedPath::Relay,
        Instant::now() + RELAY_SELECTION_TIMEOUT,
    )
    .await
    .map_err(direct_failure_to_anyhow)?;
    eprintln!("连接路径：relay");
    copy_stdio(&mut stream).await
}

async fn receive_candidates(
    control: &mut WsStream,
    session_id: Uuid,
    deadline: Instant,
) -> std::result::Result<Vec<SocketAddr>, DirectFailure> {
    loop {
        match receive_control_until(control, deadline).await? {
            ControlMessage::Candidates {
                session_id: received,
                candidates,
            } if received == session_id => return Ok(candidates),
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id => return Err(DirectFailure::RelaySelected),
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                if code == "network" || code == "timeout" {
                    return Err(DirectFailure::Network(message));
                }
                return Err(DirectFailure::Fatal(anyhow!(
                    "server rejected connection ({code}): {message}"
                )));
            }
            _ => {}
        }
    }
}

async fn wait_quic_ready(
    control: &mut super::api::WsStream,
    session_id: Uuid,
    deadline: Instant,
) -> std::result::Result<(), DirectFailure> {
    loop {
        match receive_control_until(control, deadline).await? {
            ControlMessage::QuicReady {
                session_id: received,
            } if received == session_id => return Ok(()),
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id => return Err(DirectFailure::RelaySelected),
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                if code == "network" || code == "timeout" {
                    return Err(DirectFailure::Network(message));
                }
                return Err(DirectFailure::Fatal(anyhow!(
                    "server rejected connection ({code}): {message}"
                )));
            }
            _ => {}
        }
    }
}

async fn wait_activated(
    control: &mut super::api::WsStream,
    session_id: Uuid,
    expected: SelectedPath,
    deadline: Instant,
) -> std::result::Result<(), DirectFailure> {
    loop {
        match receive_control_until(control, deadline).await? {
            ControlMessage::Activated {
                session_id: received,
                path,
            } if received == session_id => {
                if path == expected {
                    return Ok(());
                }
                if path == SelectedPath::Relay {
                    return Err(DirectFailure::RelaySelected);
                }
                return Err(DirectFailure::Fatal(anyhow!(
                    "server activated an unexpected path"
                )));
            }
            ControlMessage::SelectRelay {
                session_id: received,
            } if received == session_id => return Err(DirectFailure::RelaySelected),
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                if code == "network" || code == "timeout" {
                    return Err(DirectFailure::Network(message));
                }
                return Err(DirectFailure::Fatal(anyhow!(
                    "server rejected connection ({code}): {message}"
                )));
            }
            _ => {}
        }
    }
}

async fn next_control(control: &mut WsStream) -> Result<ControlMessage> {
    loop {
        let message = control
            .next()
            .await
            .context("control WebSocket ended")?
            .context("read control WebSocket")?;
        if matches!(message, Message::Ping(_) | Message::Pong(_)) {
            continue;
        }
        return Api::control_message(message);
    }
}

async fn receive_control_until(
    control: &mut WsStream,
    deadline: Instant,
) -> std::result::Result<ControlMessage, DirectFailure> {
    timeout_at(deadline, next_control(control))
        .await
        .map_err(|_| DirectFailure::Network("direct path deadline expired".to_owned()))?
        .map_err(DirectFailure::Fatal)
}

async fn copy_stdio<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let to_remote = async {
        tokio::io::copy(&mut stdin, &mut writer)
            .await
            .context("read SSH bytes from stdin")?;
        writer.shutdown().await.context("finish SSH input stream")
    };
    let to_stdout = async {
        tokio::io::copy(&mut reader, &mut stdout)
            .await
            .context("write SSH bytes to stdout")?;
        stdout.flush().await.context("flush SSH stdout")
    };
    tokio::pin!(to_remote, to_stdout);
    tokio::select! {
        result = &mut to_remote => {
            result?;
            to_stdout.await
        }
        result = &mut to_stdout => result,
    }
}

async fn timeout_write_frame<W, T>(stream: &mut W, message: &T, duration: Duration) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let payload = serde_json::to_vec(message).context("encode QUIC handshake frame")?;
    anyhow::ensure!(
        payload.len() <= MAX_HANDSHAKE_FRAME,
        "QUIC handshake frame is too large"
    );
    tokio::time::timeout(duration, async {
        stream.write_u32(payload.len() as u32).await?;
        stream.write_all(&payload).await?;
        stream.flush().await
    })
    .await
    .context("write QUIC handshake frame timed out")?
    .context("write QUIC handshake frame")
}

async fn timeout_read_frame<R, T>(stream: &mut R, duration: Duration) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> serde::Deserialize<'de>,
{
    tokio::time::timeout(duration, async {
        let size = stream.read_u32().await? as usize;
        anyhow::ensure!(
            size <= MAX_HANDSHAKE_FRAME,
            "QUIC handshake frame is too large"
        );
        let mut frame = vec![0; size];
        stream.read_exact(&mut frame).await?;
        serde_json::from_slice(&frame).context("decode QUIC handshake frame")
    })
    .await
    .context("read QUIC handshake frame timed out")?
}

fn classify_transport(error: TransportError) -> DirectFailure {
    match error {
        TransportError::Authentication(_)
        | TransportError::ProtocolViolation(_)
        | TransportError::Tls(_) => DirectFailure::Fatal(error.into()),
        TransportError::Configuration(_) => DirectFailure::Fatal(error.into()),
        TransportError::Network(_)
        | TransportError::Timeout(_)
        | TransportError::Quic(_)
        | TransportError::Stun(_) => {
            if error
                .to_string()
                .to_ascii_lowercase()
                .contains("certificate")
            {
                DirectFailure::Fatal(error.into())
            } else {
                DirectFailure::Network(error.to_string())
            }
        }
        TransportError::WebSocket(_) => DirectFailure::Network(error.to_string()),
    }
}

fn classify_anyhow(error: anyhow::Error) -> DirectFailure {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<TransportError>()
            .is_some_and(|transport| {
                matches!(
                    transport,
                    TransportError::Authentication(_)
                        | TransportError::ProtocolViolation(_)
                        | TransportError::Configuration(_)
                        | TransportError::Tls(_)
                )
            })
    }) || error.chain().any(|cause| {
        cause
            .downcast_ref::<DirectAuthenticationFailure>()
            .is_some()
    }) {
        return DirectFailure::Fatal(error);
    }
    if error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some()
            || cause
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
    }) {
        DirectFailure::Network(error.to_string())
    } else {
        DirectFailure::Fatal(error)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("direct authentication failed: {0}")]
struct DirectAuthenticationFailure(String);

fn as_auth_failure(error: anyhow::Error) -> anyhow::Error {
    anyhow!(DirectAuthenticationFailure(error.to_string()))
}

fn ensure_auth(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(DirectAuthenticationFailure(message.to_owned())))
    }
}

fn fingerprint(certificate_der: &[u8]) -> String {
    format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(certificate_der))
    )
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

fn direct_failure_to_anyhow(error: DirectFailure) -> anyhow::Error {
    match error {
        DirectFailure::Network(message) => anyhow!("network path unavailable: {message}"),
        DirectFailure::Fatal(error) => error,
        DirectFailure::RelaySelected => anyhow!("server selected relay path"),
    }
}
