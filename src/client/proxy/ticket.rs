use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{ControlMessage, RouteMode, TunnelTicketClaims},
    transport::IrohByteStream,
};

use super::{Api, SshAuthenticationFailure, WsStream, ensure_auth, server_setup_error};

const MAX_TICKET_FRAME: usize = 8 * 1024;

pub(super) struct TunnelOffer {
    pub(super) ticket: String,
    pub(super) target_endpoint_id: String,
    pub(super) route_mode: RouteMode,
    pub(super) expires_at: u64,
}

pub(super) async fn next_offer(
    control: &mut WsStream,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: &str,
    issuer: &str,
    expected_mode: RouteMode,
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
                route_mode,
            } if received == session_id => {
                ensure_auth(
                    route_mode == expected_mode,
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
                    route_mode,
                    expires_at: claims.exp,
                });
            }
            ControlMessage::Error {
                session_id: Some(received),
                code,
                message,
            } if received == session_id => {
                return Err(server_setup_error(code, message));
            }
            ControlMessage::Error {
                session_id: None,
                code,
                message,
            } => return Err(server_setup_error(code, message)),
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
    expected_mode: RouteMode,
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
        claims.route_mode == expected_mode,
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

pub(in crate::client) async fn read_ticket(stream: &mut IrohByteStream) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::super::{RouteNetworkFailure, attempt::classify_anyhow_network_error};
    use super::*;
    use crate::{
        protocol::RouteMode,
        transport::{RelayChoice, accept_peer, connect_peer},
    };
    use iroh::{Endpoint, SecretKey, endpoint::presets};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    async fn local_ticket_streams(
        initial_frame: &[u8],
    ) -> (Endpoint, Endpoint, IrohByteStream, IrohByteStream) {
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
        let accept_endpoint = client.clone();
        let accepting = tokio::spawn(async move { accept_peer(&accept_endpoint).await });
        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            connect_peer(&agent, client_addr, &RelayChoice::DirectOnly),
        )
        .await
        .expect("target connection handshake timed out")
        .expect("target connects to accepting client");
        let incoming = tokio::time::timeout(Duration::from_secs(5), accepting)
            .await
            .expect("client did not accept target")
            .expect("client accept task panicked")
            .expect("accept target connection");
        let target_stream =
            tokio::time::timeout(Duration::from_secs(5), IrohByteStream::open_bi(connection))
                .await
                .expect("target stream open timed out")
                .expect("target opens ticket stream");
        let mut target_stream = target_stream;
        target_stream
            .write_all(initial_frame)
            .await
            .expect("write initial ticket bytes");
        target_stream
            .flush()
            .await
            .expect("flush initial ticket bytes");
        let client_stream =
            tokio::time::timeout(Duration::from_secs(5), IrohByteStream::accept_bi(incoming))
                .await
                .expect("client stream accept timed out")
                .expect("client accepts ticket stream");
        (client, agent, target_stream, client_stream)
    }

    #[test]
    fn expired_session_ticket_is_authentication_not_route_retry() {
        let session_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let client_endpoint_id = SecretKey::generate().public().to_string();
        let target_endpoint_id = SecretKey::generate().public().to_string();
        let claims = TunnelTicketClaims {
            session_id,
            user_id: Uuid::new_v4(),
            login_session_id: Uuid::new_v4(),
            target_id,
            client_endpoint_id: client_endpoint_id.clone(),
            target_endpoint_id: target_endpoint_id.clone(),
            route_mode: RouteMode::PrivateDirect,
            iss: "https://kmesh.test:9443".to_owned(),
            aud: TUNNEL_TICKET_AUDIENCE.to_owned(),
            iat: 1,
            exp: 1,
        };
        let error = validate_offer(
            &claims,
            session_id,
            target_id,
            &client_endpoint_id,
            &target_endpoint_id,
            RouteMode::PrivateDirect,
        )
        .expect_err("expired session ticket must be rejected");
        assert!(error.downcast_ref::<SshAuthenticationFailure>().is_some());
        assert!(
            classify_anyhow_network_error(error, RouteMode::PrivateDirect)
                .downcast_ref::<RouteNetworkFailure>()
                .is_none()
        );
    }

    #[tokio::test]
    async fn partial_ticket_disconnect_is_retryable_but_invalid_frame_is_authentication() {
        let (_client, _agent, _target_stream, mut client_stream) =
            local_ticket_streams(&0u32.to_be_bytes()).await;
        let invalid = tokio::time::timeout(Duration::from_secs(5), read_ticket(&mut client_stream))
            .await
            .expect("invalid ticket frame read timed out")
            .expect_err("zero-length ticket frame must be rejected");
        assert!(invalid.downcast_ref::<SshAuthenticationFailure>().is_some());
        assert!(
            classify_anyhow_network_error(invalid, RouteMode::PrivateDirect)
                .downcast_ref::<RouteNetworkFailure>()
                .is_none()
        );

        drop(client_stream);
        let mut partial_frame = 32u32.to_be_bytes().to_vec();
        partial_frame.extend_from_slice(b"partial");
        let (_client, _agent, mut target_stream, mut client_stream) =
            local_ticket_streams(&partial_frame).await;
        let read_task = tokio::spawn(async move { read_ticket(&mut client_stream).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        target_stream.reset().expect("reset partial ticket stream");
        let network = tokio::time::timeout(Duration::from_secs(5), read_task)
            .await
            .expect("partial ticket reader did not observe the stream reset")
            .expect("partial ticket reader task panicked")
            .expect_err("reset during a partial ticket must fail");
        assert!(network.downcast_ref::<SshAuthenticationFailure>().is_none());
        assert!(
            classify_anyhow_network_error(network, RouteMode::PrivateDirect)
                .downcast_ref::<RouteNetworkFailure>()
                .is_some()
        );
    }
}
