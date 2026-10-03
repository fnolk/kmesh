use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use iroh::{Endpoint, EndpointAddr, SecretKey, Watcher, endpoint::PathEvent};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{ControlMessage, RelayMode, TransportInfo, TunnelTicketClaims},
    transport::{
        IrohByteStream, IrohEndpointOptions, IrohPathKind, RelayChoice, TransportError,
        connect_peer, create_endpoint, is_auth_failure_source, validate_endpoint_addr,
    },
};

use super::{
    ClientContext,
    agent::ensure_auth,
    api::{Api, WsStream},
    auth,
};

const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SESSION_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TICKET_FRAME: usize = 8 * 1024;

struct TunnelOffer {
    ticket: String,
    target_endpoint_addr: EndpointAddr,
    relay_mode: RelayMode,
}

struct OpenSshSession {
    _endpoint: Endpoint,
    stream: IrohByteStream,
}

#[derive(Debug, thiserror::Error)]
#[error("SSH access authentication failed: {0}")]
struct SshAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("private relay network path failed: {0}")]
struct PrivateNetworkFailure(#[source] anyhow::Error);

pub async fn run(context: &ClientContext, target_id: Uuid) -> Result<()> {
    let access_token = auth::valid_access_token(context).await?;
    let transport_info = context.api.transport_info().await?;
    let mut control = connect_control(context, &access_token).await?;
    let relay_mode = if transport_info.private_relay_url.is_some() {
        RelayMode::Private
    } else {
        RelayMode::PublicDefault
    };
    let (first_session_id, first_secret_key) = new_attempt_identity();
    let (session_id, ssh_session, mut control) = match open_ssh_session(
        context,
        &mut control,
        &transport_info,
        target_id,
        first_session_id,
        first_secret_key,
        relay_mode,
    )
    .await
    {
        Ok(session) => (first_session_id, session, control),
        Err(error)
            if relay_mode == RelayMode::Private
                && error.downcast_ref::<PrivateNetworkFailure>().is_some() =>
        {
            close_session(&mut control, first_session_id, "private_relay_failed")
                .await
                .context("close pending private SSH session before public retry")?;
            drop(control);
            let public_access_token = auth::valid_access_token(context)
                .await
                .context("refresh access token before public relay retry")?;
            let mut public_control = connect_control(context, &public_access_token)
                .await
                .context("reconnect kmesh control channel before public relay retry")?;
            let (public_session_id, public_secret_key) = new_attempt_identity();
            let session = match open_ssh_session(
                context,
                &mut public_control,
                &transport_info,
                target_id,
                public_session_id,
                public_secret_key,
                RelayMode::PublicDefault,
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    close_session_best_effort(
                        &mut public_control,
                        public_session_id,
                        "public_relay_setup_failed",
                    )
                    .await;
                    return Err(error);
                }
            };
            (public_session_id, session, public_control)
        }
        Err(error) => {
            close_session_best_effort(&mut control, first_session_id, "ssh_setup_failed").await;
            return Err(error);
        }
    };
    let OpenSshSession {
        _endpoint,
        mut stream,
    } = ssh_session;

    match stream.selected_path() {
        Some(path) if path.kind == IrohPathKind::Direct => {
            eprintln!("连接路径：P2P 直连 ({})", path.remote_address);
        }
        Some(path) => eprintln!("连接路径：Iroh 中继 ({})", path.remote_address),
        None => eprintln!("连接已建立；Iroh 正在选择网络路径。"),
    }

    let path_connection = stream.connection().clone();
    let mut path_events = path_connection.path_events();
    let path_task = tokio::spawn(async move {
        while let Some(event) = path_events.next().await {
            if let PathEvent::Selected { remote_addr, .. } = event {
                let label = if remote_addr.is_relay() {
                    "Iroh 中继"
                } else {
                    "P2P 直连"
                };
                eprintln!("连接路径切换：{label} ({remote_addr})");
            }
        }
    });
    let copy_result = copy_stdio(&mut stream).await;
    path_task.abort();
    let _ = path_task.await;
    if let Err(error) = copy_result {
        let _ = stream.reset();
        let _ = Api::send_control(
            &mut control,
            &ControlMessage::Close {
                session_id,
                reason: "client_ssh_stream_failed".to_owned(),
            },
        )
        .await;
        return Err(error).context("copy local SSH stdio over Iroh");
    }
    if let Err(error) = Api::send_control(
        &mut control,
        &ControlMessage::Close {
            session_id,
            reason: "ssh_stream_complete".to_owned(),
        },
    )
    .await
    {
        tracing::debug!(session = %session_id, error = %error, "SSH finished after control channel disconnected");
    }
    Ok(())
}

async fn connect_control(context: &ClientContext, access_token: &str) -> Result<WsStream> {
    tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        context.api.connect_control(access_token),
    )
    .await
    .context("connecting to kmesh control channel timed out")?
}

fn new_attempt_identity() -> (Uuid, SecretKey) {
    (Uuid::new_v4(), SecretKey::generate())
}

async fn open_ssh_session(
    context: &ClientContext,
    control: &mut WsStream,
    transport_info: &TransportInfo,
    target_id: Uuid,
    session_id: Uuid,
    secret_key: SecretKey,
    relay_mode: RelayMode,
) -> Result<OpenSshSession> {
    let relay_choice = endpoint_relay_choice(context, transport_info, relay_mode)?;
    let client_endpoint_id = secret_key.public().to_string();
    Api::send_control(
        control,
        &ControlMessage::Open {
            session_id,
            target_id,
            client_endpoint_id: client_endpoint_id.clone(),
            relay_mode,
        },
    )
    .await?;
    let offer = match tokio::time::timeout(
        SESSION_SETUP_TIMEOUT,
        next_offer(
            control,
            session_id,
            target_id,
            &client_endpoint_id,
            context.api.issuer(),
            &relay_choice,
            relay_mode,
        ),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(private_network_timeout(
                relay_mode,
                "waiting for target Iroh offer",
            ));
        }
    };
    anyhow::ensure!(
        offer.relay_mode == relay_mode,
        "offer relay mode differs from request"
    );
    let target_ip_addrs = offer
        .target_endpoint_addr
        .ip_addrs()
        .copied()
        .collect::<Vec<_>>();
    tracing::debug!(
        session = %session_id,
        relay_mode = ?offer.relay_mode,
        target_endpoint_id = %offer.target_endpoint_addr.id,
        target_ip_addrs = ?target_ip_addrs,
        "received authenticated Iroh target candidates"
    );

    let endpoint = create_endpoint(
        secret_key,
        false,
        IrohEndpointOptions {
            relay_choice: relay_choice.clone(),
            tls: context.config.tls.clone(),
        },
    )
    .await
    .map_err(anyhow::Error::new)
    .context("create client Iroh endpoint")?;
    let connection = match tokio::time::timeout(
        SESSION_SETUP_TIMEOUT,
        connect_peer(&endpoint, offer.target_endpoint_addr.clone(), &relay_choice),
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            return Err(classify_client_transport_error(
                &endpoint, error, relay_mode,
            ));
        }
        Err(_) => {
            if let Some(error) = private_relay_auth_failure(&endpoint, relay_mode) {
                return Err(error);
            }
            return Err(private_network_timeout(
                relay_mode,
                "connecting to target Iroh endpoint",
            ));
        }
    };
    let mut stream = IrohByteStream::open_bi(connection)
        .await
        .map_err(|error| classify_client_transport_error(&endpoint, error, relay_mode))
        .context("open SSH Iroh stream")?;
    if let Err(error) = write_ticket(&mut stream, &offer.ticket)
        .await
        .context("send signed SSH ticket to target")
    {
        let _ = stream.reset();
        return Err(classify_anyhow_network_error(error, relay_mode));
    }
    let activated = match tokio::time::timeout(
        SESSION_SETUP_TIMEOUT,
        wait_activated(control, session_id, relay_mode),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(private_network_timeout(
            relay_mode,
            "waiting for SSH activation",
        )),
    };
    if let Err(error) = activated {
        let _ = stream.reset();
        return Err(error);
    }
    Ok(OpenSshSession {
        _endpoint: endpoint,
        stream,
    })
}

fn endpoint_relay_choice(
    context: &ClientContext,
    info: &TransportInfo,
    relay_mode: RelayMode,
) -> Result<RelayChoice> {
    match relay_mode {
        RelayMode::Private => {
            let relay_url = reqwest::Url::parse(
                info.private_relay_url
                    .as_deref()
                    .context("private relay mode requested without a configured private relay")?,
            )
            .context("parse private Iroh relay URL")?;
            let control_origin = reqwest::Url::parse(context.api.issuer())
                .context("parse configured kmesh server URL")?;
            anyhow::ensure!(
                relay_url == control_origin,
                "private Iroh relay URL differs from the configured kmesh server"
            );
            Ok(RelayChoice::Private {
                url: relay_url,
                qad_port: info.qad_port,
            })
        }
        RelayMode::PublicDefault => Ok(RelayChoice::PublicDefault),
    }
}

fn classify_transport_error(error: TransportError, relay_mode: RelayMode) -> anyhow::Error {
    if relay_mode == RelayMode::Private && error.is_network_failure() {
        anyhow::Error::new(PrivateNetworkFailure(anyhow::Error::new(error)))
    } else {
        anyhow::Error::new(error)
    }
}

fn classify_client_transport_error(
    endpoint: &Endpoint,
    error: TransportError,
    relay_mode: RelayMode,
) -> anyhow::Error {
    if let Some(error) = private_relay_auth_failure(endpoint, relay_mode) {
        error
    } else {
        classify_transport_error(error, relay_mode)
    }
}

fn private_relay_auth_failure(endpoint: &Endpoint, relay_mode: RelayMode) -> Option<anyhow::Error> {
    if relay_mode != RelayMode::Private {
        return None;
    }
    endpoint
        .home_relay_status()
        .get()
        .into_iter()
        .find_map(|status| {
            if let Some(reason) = status.auth_denied_reason() {
                return Some(anyhow!(SshAuthenticationFailure(format!(
                    "private Iroh relay denied this endpoint: {reason}"
                ))));
            }
            status.last_error().and_then(|error| {
                is_auth_failure_source(error)
                    .then(|| anyhow!(SshAuthenticationFailure(error.to_string())))
            })
        })
}

fn server_setup_error(code: String, message: String, relay_mode: RelayMode) -> anyhow::Error {
    match code.as_str() {
        "authentication" | "authorization" => {
            anyhow!(SshAuthenticationFailure(message))
        }
        "network" if relay_mode == RelayMode::Private => {
            anyhow::Error::new(PrivateNetworkFailure(anyhow!(message)))
        }
        _ => anyhow!("server could not prepare SSH access: {message}"),
    }
}

fn classify_anyhow_network_error(error: anyhow::Error, relay_mode: RelayMode) -> anyhow::Error {
    if relay_mode == RelayMode::Private
        && error
            .chain()
            .any(crate::transport::is_network_failure_source)
    {
        anyhow::Error::new(PrivateNetworkFailure(error))
    } else {
        error
    }
}

fn private_network_timeout(relay_mode: RelayMode, stage: &'static str) -> anyhow::Error {
    let error = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{stage} timed out"),
    ));
    classify_anyhow_network_error(error, relay_mode)
}

async fn close_session(control: &mut WsStream, session_id: Uuid, reason: &str) -> Result<()> {
    Api::send_control(
        control,
        &ControlMessage::Close {
            session_id,
            reason: reason.to_owned(),
        },
    )
    .await
}

async fn close_session_best_effort(control: &mut WsStream, session_id: Uuid, reason: &str) {
    if let Err(error) = close_session(control, session_id, reason).await {
        tracing::debug!(session = %session_id, error = %error, "failed to close pending SSH session");
    }
}

async fn next_offer(
    control: &mut WsStream,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: &str,
    issuer: &str,
    relay_choice: &RelayChoice,
    expected_mode: RelayMode,
) -> Result<TunnelOffer> {
    loop {
        let message = control
            .next()
            .await
            .context("control WebSocket ended before target offer")?
            .context("read control WebSocket")?;
        if matches!(message, Message::Ping(_) | Message::Pong(_)) {
            continue;
        }
        match Api::control_message(message)? {
            ControlMessage::Offer {
                session_id: received,
                target_id: offered_target,
                ticket,
                client_endpoint_id: offered_client,
                target_endpoint_addr,
                ticket_public_key_pem,
                relay_mode,
            } if received == session_id => {
                ensure_auth(
                    relay_mode == expected_mode,
                    "offer relay mode differs from the requested mode",
                )?;
                ensure_auth(
                    offered_target == target_id,
                    "offer target ID differs from request",
                )?;
                ensure_auth(
                    offered_client == client_endpoint_id,
                    "offer client EndpointId differs from this SSH connection",
                )?;
                let claims = decode_tunnel_ticket(&ticket, &ticket_public_key_pem, issuer)
                    .map_err(|error| anyhow!(SshAuthenticationFailure(error.to_string())))?;
                validate_offer(
                    &claims,
                    session_id,
                    target_id,
                    client_endpoint_id,
                    &target_endpoint_addr,
                    relay_choice,
                    expected_mode,
                )?;
                return Ok(TunnelOffer {
                    ticket,
                    target_endpoint_addr,
                    relay_mode,
                });
            }
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                return Err(server_setup_error(code, message, expected_mode));
            }
            _ => {
                tracing::debug!(session = %session_id, "ignoring unexpected control message before target offer")
            }
        }
    }
}

fn validate_offer(
    claims: &TunnelTicketClaims,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: &str,
    target_endpoint_addr: &EndpointAddr,
    relay_choice: &RelayChoice,
    expected_mode: RelayMode,
) -> Result<()> {
    ensure_auth(
        claims.session_id == session_id,
        "ticket session ID mismatch",
    )?;
    ensure_auth(claims.target_id == target_id, "ticket target ID mismatch")?;
    ensure_auth(
        claims.client_endpoint_id == client_endpoint_id,
        "ticket client EndpointId mismatch",
    )?;
    ensure_auth(
        claims.target_endpoint_id == target_endpoint_addr.id.to_string(),
        "ticket target EndpointId mismatch",
    )?;
    ensure_auth(
        claims.relay_mode == expected_mode,
        "ticket relay mode differs from the requested mode",
    )?;
    validate_endpoint_addr(target_endpoint_addr, relay_choice)
        .map_err(|error| anyhow!(SshAuthenticationFailure(error.to_string())))?;
    ensure_auth(
        claims.aud == TUNNEL_TICKET_AUDIENCE,
        "ticket audience mismatch",
    )?;
    ensure_auth(
        claims.exp
            > std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system clock is before Unix epoch")?
                .as_secs(),
        "ticket has expired",
    )?;
    client_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(SshAuthenticationFailure(
                "client EndpointId is invalid".to_owned()
            ))
        })?;
    Ok(())
}

async fn write_ticket(stream: &mut IrohByteStream, ticket: &str) -> Result<()> {
    let bytes = ticket.as_bytes();
    anyhow::ensure!(
        bytes.len() <= MAX_TICKET_FRAME,
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

async fn wait_activated(
    control: &mut WsStream,
    session_id: Uuid,
    relay_mode: RelayMode,
) -> Result<()> {
    loop {
        let message = control
            .next()
            .await
            .context("control WebSocket ended before SSH activation")?
            .context("read control WebSocket")?;
        if matches!(message, Message::Ping(_) | Message::Pong(_)) {
            continue;
        }
        match Api::control_message(message)? {
            ControlMessage::Activated {
                session_id: received,
            } if received == session_id => return Ok(()),
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                return Err(server_setup_error(code, message, relay_mode));
            }
            ControlMessage::Close {
                session_id: received,
                reason,
            } if received == session_id => {
                bail!("server closed SSH session before activation: {reason}");
            }
            _ => {
                tracing::debug!(session = %session_id, "ignoring unexpected control message before activation")
            }
        }
    }
}

async fn copy_stdio(stream: &mut IrohByteStream) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    {
        let (mut reader, mut writer) = tokio::io::split(&mut *stream);
        let upload = async {
            tokio::io::copy(&mut stdin, &mut writer).await?;
            writer.shutdown().await
        };
        let download = async {
            tokio::io::copy(&mut reader, &mut stdout).await?;
            stdout.flush().await
        };
        tokio::try_join!(upload, download).context("copy bidirectional SSH stdio")?;
    };
    stream
        .finish_send_and_wait()
        .await
        .context("wait for target to acknowledge final SSH bytes")?;
    stream
        .connection()
        .close(iroh::endpoint::VarInt::from_u32(0), b"ssh session complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PrivateNetworkFailure, classify_transport_error, new_attempt_identity, server_setup_error,
    };
    use crate::{protocol::RelayMode, transport::TransportError};
    use std::io;

    #[test]
    fn retryable_private_failures_use_a_fresh_session_and_endpoint_key() {
        let (private_session, private_key) = new_attempt_identity();
        let (public_session, public_key) = new_attempt_identity();

        assert_ne!(private_session, public_session);
        assert_ne!(private_key.public(), public_key.public());
    }

    #[test]
    fn only_network_errors_in_private_mode_produce_the_retry_marker() {
        let private_network = classify_transport_error(
            TransportError::Network(io::Error::from(io::ErrorKind::ConnectionRefused)),
            RelayMode::Private,
        );
        assert!(
            private_network
                .downcast_ref::<PrivateNetworkFailure>()
                .is_some()
        );

        let private_auth = classify_transport_error(
            TransportError::Authentication("denied".to_owned()),
            RelayMode::Private,
        );
        assert!(
            private_auth
                .downcast_ref::<PrivateNetworkFailure>()
                .is_none()
        );

        let public_network =
            classify_transport_error(TransportError::Timeout("relay"), RelayMode::PublicDefault);
        assert!(
            public_network
                .downcast_ref::<PrivateNetworkFailure>()
                .is_none()
        );

        let server_auth = server_setup_error(
            "authorization".to_owned(),
            "access denied".to_owned(),
            RelayMode::Private,
        );
        assert!(
            server_auth
                .downcast_ref::<PrivateNetworkFailure>()
                .is_none()
        );
    }
}
