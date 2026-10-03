use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use iroh::{EndpointAddr, SecretKey, endpoint::PathEvent};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{ControlMessage, TransportInfo, TunnelTicketClaims},
    transport::{IrohByteStream, IrohEndpointOptions, IrohPathKind, connect_peer, create_endpoint},
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
}

#[derive(Debug, thiserror::Error)]
#[error("SSH access authentication failed: {0}")]
struct SshAuthenticationFailure(String);

pub async fn run(context: &ClientContext, target_id: Uuid) -> Result<()> {
    let access_token = auth::valid_access_token(context).await?;
    let secret_key = SecretKey::generate();
    let client_endpoint_id = secret_key.public().to_string();
    let session_id = Uuid::new_v4();
    let mut control = tokio::time::timeout(
        CONTROL_CONNECT_TIMEOUT,
        context.api.connect_control(&access_token),
    )
    .await
    .context("connecting to kmesh control channel timed out")??;
    Api::send_control(
        &mut control,
        &ControlMessage::Open {
            session_id,
            target_id,
            client_endpoint_id: client_endpoint_id.clone(),
        },
    )
    .await?;
    let offer = tokio::time::timeout(
        SESSION_SETUP_TIMEOUT,
        next_offer(
            &mut control,
            session_id,
            target_id,
            &client_endpoint_id,
            context.api.issuer(),
        ),
    )
    .await
    .context("waiting for target Iroh offer timed out")??;
    let transport_info = context.api.transport_info().await?;
    let endpoint = create_endpoint(
        secret_key,
        false,
        endpoint_options(context, transport_info)?,
    )
    .await
    .map_err(anyhow::Error::new)
    .context("create client Iroh endpoint")?;
    let connection = tokio::time::timeout(
        SESSION_SETUP_TIMEOUT,
        connect_peer(&endpoint, offer.target_endpoint_addr.clone()),
    )
    .await
    .context("connecting to target Iroh endpoint timed out")?
    .map_err(anyhow::Error::new)
    .context("connect to target Iroh endpoint")?;
    let mut stream = IrohByteStream::open_bi(connection)
        .await
        .map_err(anyhow::Error::new)
        .context("open SSH Iroh stream")?;
    write_ticket(&mut stream, &offer.ticket)
        .await
        .context("send signed SSH ticket to target")?;
    tokio::time::timeout(
        SESSION_SETUP_TIMEOUT,
        wait_activated(&mut control, session_id),
    )
    .await
    .context("waiting for SSH activation timed out")??;

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

async fn next_offer(
    control: &mut WsStream,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: &str,
    issuer: &str,
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
            } if received == session_id => {
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
                    issuer,
                )?;
                return Ok(TunnelOffer {
                    ticket,
                    target_endpoint_addr,
                });
            }
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                if code == "authentication" || code == "authorization" {
                    bail!(SshAuthenticationFailure(message));
                }
                bail!("server could not prepare SSH access: {message}");
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
    self_relay_url: &str,
) -> Result<()> {
    let expected_relay: iroh::RelayUrl = reqwest::Url::parse(self_relay_url)
        .context("parse configured self-relay URL")?
        .into();
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
    let relay_urls = target_endpoint_addr.relay_urls().collect::<Vec<_>>();
    ensure_auth(
        relay_urls.len() == 1 && relay_urls[0] == &expected_relay,
        "target offer does not use the configured private relay",
    )?;
    ensure_auth(
        target_endpoint_addr
            .addrs
            .iter()
            .all(|address| match address {
                iroh::TransportAddr::Ip(_) => true,
                iroh::TransportAddr::Relay(url) => url == &expected_relay,
                iroh::TransportAddr::Custom(_) => false,
                _ => false,
            }),
        "target offer contains an unrecognized transport address",
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

async fn wait_activated(control: &mut WsStream, session_id: Uuid) -> Result<()> {
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
                if code == "authentication" || code == "authorization" {
                    bail!(SshAuthenticationFailure(message));
                }
                bail!("server rejected SSH session before activation: {message}");
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
