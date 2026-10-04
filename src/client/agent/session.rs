use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use iroh::{Endpoint, SecretKey};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::mpsc,
    time::{Instant, timeout, timeout_at},
};
use uuid::Uuid;

use crate::{
    client::route::{DIRECT_PUNCH_TIMEOUT, SSH_SETUP_TIMEOUT, attempt_timeout},
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{
        AgentCredentials, ControlMessage, DiscoveryResult, NativePlan, RouteMode, TransportInfo,
        TunnelTicketClaims,
    },
    transport::{
        IrohByteStream, RelayChoice, TransportError, connect_peer, create_endpoint,
        discover_ipv4_mappings, validate_endpoint_addr, wait_endpoint_ready,
        wait_for_selected_path,
    },
};

use super::{
    AgentAuthenticationFailure, ClientContext, MAX_TICKET_FRAME, TunnelOffer, ensure_auth,
    route::endpoint_options, server_session_error, transport_error,
};
use super::{control::next_session_message, punch::run_target_punch};

pub(super) async fn run_agent_session(
    context: &ClientContext,
    credentials: &AgentCredentials,
    stable_device_key: SecretKey,
    transport_info: TransportInfo,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: String,
    route_mode: RouteMode,
    expires_at: i64,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs() as i64;
    let remaining_secs = expires_at.saturating_sub(now);
    ensure_auth(remaining_secs > 0, "agent session preparation has expired")?;
    let ticket_deadline =
        Instant::now() + Duration::from_secs(remaining_secs as u64).min(SSH_SETUP_TIMEOUT);
    let deadline = ticket_deadline.min(Instant::now() + attempt_timeout(route_mode));
    let client_id = client_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(AgentAuthenticationFailure(
                "prepared client EndpointId is invalid".to_owned()
            ))
        })?;
    let data_key = SecretKey::generate();
    let data_id = data_key.public();
    let signature = stable_device_key
        .sign(&crate::identity::agent_session_identity_payload(
            session_id, target_id, route_mode, &data_id, expires_at,
        ))
        .to_bytes()
        .to_vec();
    outbound
        .send(ControlMessage::AgentIdentity {
            session_id,
            route_mode,
            target_data_endpoint_id: data_id.to_string(),
            signature,
        })
        .await
        .context("register per-session target data identity")?;

    match next_session_message(&mut control_rx, session_id, deadline).await? {
        None => return Ok(()),
        Some(ControlMessage::IdentityAccepted {
            session_id: accepted,
            route_mode: accepted_mode,
        }) if accepted == session_id && accepted_mode == route_mode => {}
        _ => {
            return Err(anyhow!(AgentAuthenticationFailure(
                "server returned an unexpected response to the signed target identity".to_owned()
            )));
        }
    }

    let route_plan = crate::client::route::route_transport_plan(
        route_mode,
        &transport_info,
        context.api.issuer(),
    )
    .context("build target route transport plan")?;
    let relay_choice = route_plan.relay_choice.clone();
    let mut discovered = None;
    if let Some(qad_plan) = route_plan.qad_plan {
        let discovery_deadline = std::cmp::min(deadline, Instant::now() + DIRECT_PUNCH_TIMEOUT);
        let discovery = tokio::select! {
            biased;
            control = next_session_message(&mut control_rx, session_id, deadline) => {
                match control? {
                    None => return Ok(()),
                    Some(_) => return Err(anyhow!(AgentAuthenticationFailure(
                        "server sent a control message before target candidate discovery completed".to_owned()
                    ))),
                }
            }
            result = discover_ipv4_mappings(&qad_plan, &context.config.tls, discovery_deadline) => {
                result.map_err(anyhow::Error::new)?
            }
        };
        let discovery_message = match discovery {
            crate::transport::MappingDiscovery::Ready(found) => {
                let message = DiscoveryResult::Ready {
                    local_socket: found.local_socket,
                    observations: found.observations.clone(),
                };
                discovered = Some(found);
                message
            }
            crate::transport::MappingDiscovery::Unavailable { reason } => {
                DiscoveryResult::Unavailable { reason }
            }
        };
        outbound
            .send(ControlMessage::CandidatesReady {
                session_id,
                route_mode,
                discovery: discovery_message,
            })
            .await
            .context("report target QAD candidate discovery")?;
    }

    let first_native_message =
        match next_session_message(&mut control_rx, session_id, deadline).await? {
            None => return Ok(()),
            Some(message) => message,
        };
    let (handoff, selection) = match first_native_message {
        ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan: NativePlan::Standard,
        } if received == session_id && mode == route_mode => {
            drop(discovered.take());
            (None, None)
        }
        ControlMessage::PunchPair {
            session_id: received,
            route_mode: mode,
            target_endpoint_id,
            client_endpoint_id: paired_client_id,
            peer_discovery,
        } if received == session_id && mode == route_mode => {
            ensure_auth(
                target_endpoint_id == data_id.to_string(),
                "server paired a different per-session target EndpointId",
            )?;
            ensure_auth(
                paired_client_id == client_endpoint_id,
                "server paired a different client EndpointId",
            )?;
            let discovered = discovered.take().ok_or_else(|| {
                anyhow!(AgentAuthenticationFailure(
                    "server requested UDP punching without successful QAD discovery".to_owned()
                ))
            })?;
            let Some(native) = run_target_punch(
                session_id,
                route_mode,
                data_id,
                client_id,
                data_key.clone(),
                discovered,
                peer_discovery,
                &mut control_rx,
                &outbound,
                deadline,
            )
            .await?
            else {
                return Ok(());
            };
            native
        }
        _ => {
            return Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected response to target QAD candidates".to_owned()
            )));
        }
    };

    let options = endpoint_options(context, &transport_info, route_mode, handoff)
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    let relay_choice = options.relay_choice.clone();
    let endpoint = tokio::select! {
        biased;
        control = next_session_message(&mut control_rx, session_id, deadline) => {
            match control? {
                None => return Ok(()),
                Some(_) => return Err(anyhow!(AgentAuthenticationFailure(
                    "server sent a control message before target Endpoint creation completed".to_owned()
                ))),
            }
        }
        result = timeout_at(deadline, create_endpoint(data_key, false, options)) => {
            result
                .context("create per-session target Iroh endpoint before expiry")?
                .map_err(anyhow::Error::new)?
        }
    };
    tokio::select! {
        biased;
        control = next_session_message(&mut control_rx, session_id, deadline) => {
            match control? {
                None => return Ok(()),
                Some(_) => return Err(anyhow!(AgentAuthenticationFailure(
                    "server sent a control message before target Endpoint readiness".to_owned()
                ))),
            }
        }
        result = timeout_at(deadline, wait_endpoint_ready(&endpoint, &relay_choice, deadline)) => {
            result
                .context("wait for per-session target relay and address readiness")?
                .map_err(anyhow::Error::new)?;
        }
    }
    let target_data_endpoint_id = endpoint.id().to_string();
    outbound
        .send(ControlMessage::AgentReady {
            session_id,
            route_mode,
            endpoint_addr: endpoint.addr(),
        })
        .await
        .context("publish per-session target Iroh endpoint")?;

    let offer = match next_session_message(&mut control_rx, session_id, deadline).await? {
        None => return Ok(()),
        Some(ControlMessage::DialOffer {
            session_id: received,
            target_id: offered_target_id,
            ticket,
            client_endpoint_id,
            client_endpoint_addr,
            ticket_public_key_pem,
            route_mode: offered_mode,
        }) if received == session_id && offered_mode == route_mode => TunnelOffer {
            session_id,
            target_id: offered_target_id,
            ticket,
            client_endpoint_id,
            client_endpoint_addr,
            ticket_public_key_pem,
            route_mode,
        },
        Some(_) => {
            return Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected control message before target dial offer".to_owned()
            )));
        }
    };
    ensure_auth(
        offer.target_id == target_id,
        "dial offer target ID differs from Prepare",
    )?;
    let claims = decode_tunnel_ticket(
        &offer.ticket,
        &offer.ticket_public_key_pem,
        context.api.issuer(),
    )
    .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;
    validate_ticket(&claims, &offer, credentials, endpoint.id())?;
    validate_endpoint_addr(&offer.client_endpoint_addr, &relay_choice)
        .map_err(anyhow::Error::new)
        .map_err(|error| anyhow!(AgentAuthenticationFailure(error.to_string())))?;

    tracing::debug!(
        session = %session_id,
        target_data_endpoint_id,
        raw_selected = selection.is_some(),
        native_handoff_selected = handoff.is_some(),
        endpoint_addr = ?endpoint.addr(),
        "per-session target endpoint ready"
    );
    handle_dial_offer(
        context,
        offer,
        endpoint,
        relay_choice,
        deadline,
        control_rx,
        outbound,
    )
    .await
}

pub(super) async fn handle_dial_offer(
    context: &ClientContext,
    offer: TunnelOffer,
    endpoint: Endpoint,
    relay_choice: RelayChoice,
    setup_deadline: Instant,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    outbound: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let connection = timeout_at(setup_deadline, async {
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
        .context("target connection exceeded the per-session expiry")?
        ?;
    let Some(connection) = connection else {
        return Ok(());
    };
    let remote_endpoint_id = connection.remote_id().to_string();
    ensure_auth(
        remote_endpoint_id == offer.client_endpoint_id,
        "Iroh peer EndpointId differs from the ticket client EndpointId",
    )?;

    let selected_path = tokio::select! {
        biased;
        control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
            control?;
            return Ok(());
        }
        result = wait_for_selected_path(&connection, offer.route_mode, setup_deadline) => {
            result.map_err(transport_error)?
        }
    };
    outbound
        .send(ControlMessage::PathReady {
            session_id: offer.session_id,
            route_mode: offer.route_mode,
            path: selected_path,
        })
        .await
        .context("report selected Iroh route to server")?;

    let stream = timeout_at(setup_deadline, async {
        tokio::select! {
            biased;
            control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
                control?;
                Ok(None)
            }
            result = IrohByteStream::open_bi(connection) => {
                result.map(Some).map_err(transport_error)
            }
        }
    })
    .await
    .context("opening the target Iroh stream exceeded the route deadline")??;
    let Some(mut stream) = stream else {
        return Ok(());
    };
    let ticket_written = timeout_at(setup_deadline, async {
        tokio::select! {
            biased;
            control = wait_for_setup_cancellation(offer.session_id, &mut control_rx) => {
                control?;
                Ok(false)
            }
            result = write_ticket(&mut stream, &offer.ticket) => {
                result.context("send signed tunnel ticket to client")?;
                Ok(true)
            }
        }
    })
    .await
    .context("writing the signed ticket exceeded the route deadline")??;
    if !ticket_written {
        return Ok(());
    }
    outbound
        .send(ControlMessage::IrohReady {
            session_id: offer.session_id,
            client_endpoint_id: remote_endpoint_id,
            target_data_endpoint_id: endpoint.id().to_string(),
            route_mode: offer.route_mode,
        })
        .await
        .context("report authenticated Iroh peer to server")?;
    if !timeout_at(
        setup_deadline,
        wait_activated(offer.session_id, &mut control_rx),
    )
    .await
    .context("target activation exceeded the per-session expiry")??
    {
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
    let paths_before_ssh = snapshot_iroh_paths(stream.connection());
    tracing::debug!(
        session = %offer.session_id,
        paths = ?paths_before_ssh,
        "target Iroh paths before SSH byte forwarding"
    );
    let result = tokio::io::copy_bidirectional(&mut ssh, &mut stream).await;
    let paths_after_ssh = snapshot_iroh_paths(stream.connection());
    match result {
        Ok((to_ssh, from_ssh)) => {
            tracing::debug!(
                session = %offer.session_id,
                ssh_bytes_to_target = to_ssh,
                ssh_bytes_from_target = from_ssh,
                paths_before = ?paths_before_ssh,
                paths_after = ?paths_after_ssh,
                "target SSH forwarding path and byte counters"
            );
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
            tracing::debug!(
                session = %offer.session_id,
                error = %error,
                paths_before = ?paths_before_ssh,
                paths_after = ?paths_after_ssh,
                "target SSH forwarding ended with an Iroh path snapshot"
            );
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
                return Err(server_session_error(&code, message));
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
        claims.route_mode == offer.route_mode,
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
                return Err(server_session_error(&code, message));
            }
            Some(ControlMessage::Close {
                session_id: received,
                ..
            }) if received == session_id => return Ok(false),
            Some(_) => {}
        }
    }
}
