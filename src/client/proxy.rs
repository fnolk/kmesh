use std::{future::Future, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use iroh::{Endpoint, SecretKey, Watcher, endpoint::PathEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{ControlMessage, RelayMode, TransportInfo, TunnelTicketClaims},
    transport::{
        IrohByteStream, IrohEndpointOptions, IrohPathKind, RelayChoice, TransportError,
        accept_peer, create_endpoint, is_auth_failure_source, wait_endpoint_ready,
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
    target_endpoint_id: String,
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
    let endpoint = create_endpoint(
        secret_key,
        true,
        IrohEndpointOptions {
            relay_choice: relay_choice.clone(),
            tls: context.config.tls.clone(),
        },
    )
    .await
    .map_err(anyhow::Error::new)
    .context("create client Iroh endpoint")?;
    let mut activated = false;
    wait_setup_step(
        control,
        &endpoint,
        session_id,
        relay_mode,
        "waiting for client Iroh endpoint readiness",
        &mut activated,
        async {
            wait_endpoint_ready(&endpoint, Duration::from_secs(20))
                .await
                .map_err(|error| classify_client_transport_error(&endpoint, error, relay_mode))
        },
    )
    .await?;
    let client_endpoint_addr = endpoint.addr();
    ensure_auth(
        client_endpoint_addr.id.to_string() == client_endpoint_id,
        "client EndpointId differs from the SSH attempt identity",
    )?;
    tracing::debug!(
        session = %session_id,
        relay_mode = ?relay_mode,
        client_endpoint_id = %client_endpoint_addr.id,
        client_ip_addrs = ?client_endpoint_addr.ip_addrs().copied().collect::<Vec<_>>(),
        "publishing prepared client Iroh candidates"
    );
    Api::send_control(
        control,
        &ControlMessage::ClientReady {
            session_id,
            relay_mode,
            client_endpoint_addr,
        },
    )
    .await?;

    let connection = wait_setup_step(
        control,
        &endpoint,
        session_id,
        relay_mode,
        "waiting for target Iroh connection",
        &mut activated,
        async {
            accept_peer(&endpoint)
                .await
                .map_err(|error| classify_client_transport_error(&endpoint, error, relay_mode))
        },
    )
    .await?;
    ensure_auth(
        connection.remote_id().to_string() == offer.target_endpoint_id,
        "Iroh peer EndpointId differs from the signed target EndpointId",
    )?;
    let mut stream = wait_setup_step(
        control,
        &endpoint,
        session_id,
        relay_mode,
        "waiting for target SSH stream",
        &mut activated,
        async {
            IrohByteStream::accept_bi(connection)
                .await
                .map_err(|error| classify_client_transport_error(&endpoint, error, relay_mode))
        },
    )
    .await?;
    let received_ticket = wait_setup_step(
        control,
        &endpoint,
        session_id,
        relay_mode,
        "waiting for signed SSH ticket",
        &mut activated,
        async { read_ticket(&mut stream).await },
    )
    .await?;
    ensure_auth(
        received_ticket == offer.ticket,
        "Iroh stream ticket differs from the signed client offer",
    )?;
    if !activated {
        tokio::time::timeout(
            SESSION_SETUP_TIMEOUT,
            wait_activated(control, session_id, relay_mode),
        )
        .await
        .map_err(|_| {
            private_relay_auth_failure(&endpoint, relay_mode).unwrap_or_else(|| {
                private_network_timeout(relay_mode, "waiting for SSH activation")
            })
        })?
        .map_err(|error| classify_anyhow_network_error(error, relay_mode))?;
    }
    Ok(OpenSshSession {
        _endpoint: endpoint,
        stream,
    })
}

async fn wait_setup_step<T>(
    control: &mut WsStream,
    endpoint: &Endpoint,
    session_id: Uuid,
    relay_mode: RelayMode,
    stage: &'static str,
    activated: &mut bool,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    let mut operation = Box::pin(operation);
    let wait = async {
        loop {
            tokio::select! {
                biased;
                result = &mut operation => {
                    return result.map_err(|error| classify_anyhow_network_error(error, relay_mode));
                }
                message = control.next() => {
                    let message = message
                        .context("control WebSocket ended during SSH setup")
                        .and_then(|message| message.context("read control WebSocket during SSH setup"))
                        .map_err(|error| classify_anyhow_network_error(error, relay_mode))?;
                    if matches!(message, Message::Ping(_) | Message::Pong(_)) {
                        continue;
                    }
                    match Api::control_message(message)? {
                        ControlMessage::Activated { session_id: received } if received == session_id => {
                            *activated = true;
                        }
                        ControlMessage::Error { session_id: Some(received), code, message }
                            if received == session_id => return Err(server_setup_error(code, message, relay_mode)),
                        ControlMessage::Close { session_id: received, reason }
                            if received == session_id => bail!("server closed SSH session during setup: {reason}"),
                        _ => tracing::debug!(session = %session_id, "ignoring unexpected control message during Iroh setup"),
                    }
                }
            }
        }
    };
    tokio::time::timeout(SESSION_SETUP_TIMEOUT, wait)
        .await
        .map_err(|_| {
            private_relay_auth_failure(endpoint, relay_mode)
                .unwrap_or_else(|| private_network_timeout(relay_mode, stage))
        })?
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
            ControlMessage::ClientOffer {
                session_id: received,
                target_id: offered_target,
                ticket,
                client_endpoint_id: offered_client,
                target_endpoint_id,
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
                    &target_endpoint_id,
                    expected_mode,
                )?;
                return Ok(TunnelOffer {
                    ticket,
                    target_endpoint_id,
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
            ControlMessage::Close {
                session_id: received,
                reason,
            } if received == session_id => {
                bail!("server closed SSH session before target offer: {reason}");
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
    target_endpoint_id: &str,
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
        claims.target_endpoint_id == target_endpoint_id,
        "ticket target EndpointId mismatch",
    )?;
    ensure_auth(
        claims.relay_mode == expected_mode,
        "ticket relay mode differs from the requested mode",
    )?;
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
    target_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(SshAuthenticationFailure(
                "target EndpointId is invalid".to_owned()
            ))
        })?;
    Ok(())
}

async fn read_ticket(stream: &mut IrohByteStream) -> Result<String> {
    let mut length_bytes = [0; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .context("read ticket frame length")?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_TICKET_FRAME {
        return Err(anyhow!(SshAuthenticationFailure(
            "ticket frame length is invalid".to_owned()
        )));
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .context("read ticket frame")?;
    String::from_utf8(bytes).map_err(|error| {
        anyhow!(SshAuthenticationFailure(format!(
            "ticket frame is not UTF-8: {error}"
        )))
    })
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
    use super::*;
    use crate::{protocol::RelayMode, transport::TransportError};
    use iroh::{Endpoint, SecretKey, endpoint::presets};
    use std::io;
    use tokio::io::AsyncWriteExt;

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

    #[tokio::test]
    async fn partial_ticket_disconnect_is_retryable_but_invalid_frame_is_authentication() {
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![crate::transport::IROH_SSH_ALPN.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind local client endpoint");
        let agent = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind local target endpoint");
        let client_addr = client.addr();
        let accepting = tokio::spawn(async move { accept_peer(&client).await });
        let connection = connect_peer(&agent, client_addr, &RelayChoice::PublicDefault)
            .await
            .expect("target connects to accepting client");
        let incoming = tokio::time::timeout(Duration::from_secs(5), accepting)
            .await
            .expect("client did not accept target")
            .expect("client accept task panicked")
            .expect("accept target connection");
        let mut target_stream = IrohByteStream::open_bi(connection)
            .await
            .expect("target opens ticket stream");
        let mut client_stream = IrohByteStream::accept_bi(incoming)
            .await
            .expect("client accepts ticket stream");

        target_stream
            .write_u32(0)
            .await
            .expect("write invalid ticket frame length");
        target_stream
            .write_u32(32)
            .await
            .expect("write partial ticket frame length");
        target_stream
            .write_all(b"partial")
            .await
            .expect("write partial ticket frame");
        target_stream.flush().await.expect("flush ticket frames");

        let invalid = read_ticket(&mut client_stream)
            .await
            .expect_err("zero-length ticket frame must be rejected");
        assert!(invalid.downcast_ref::<SshAuthenticationFailure>().is_some());
        assert!(
            classify_anyhow_network_error(invalid, RelayMode::Private)
                .downcast_ref::<PrivateNetworkFailure>()
                .is_none()
        );

        let pending_read = read_ticket(&mut client_stream);
        tokio::pin!(pending_read);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut pending_read)
                .await
                .is_err()
        );
        target_stream.reset().expect("reset partial ticket stream");
        let network = pending_read
            .await
            .expect_err("reset during a partial ticket must fail");
        assert!(network.downcast_ref::<SshAuthenticationFailure>().is_none());
        assert!(
            classify_anyhow_network_error(network, RelayMode::Private)
                .downcast_ref::<PrivateNetworkFailure>()
                .is_some()
        );
    }
}
