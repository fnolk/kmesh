use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use iroh::{Endpoint, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    identity::{TUNNEL_TICKET_AUDIENCE, decode_tunnel_ticket},
    protocol::{
        ControlMessage, DiscoveryResult, NativePlan, RouteMode, SelectedPath, TransportInfo,
        TunnelTicketClaims,
    },
    transport::{
        DiscoveredUdpSocket, HandoffOptions, IrohByteStream, IrohEndpointOptions, MappingDiscovery,
        PreparedPunch, PunchError, PunchIdentity, PunchRole, RelayChoice, TransportError,
        accept_peer, create_endpoint, discover_ipv4_mappings, is_auth_failure_source,
        wait_endpoint_ready, wait_for_selected_path,
    },
};

use super::super::{
    ClientContext,
    api::{Api, WsStream},
    route::{DIRECT_PUNCH_TIMEOUT, SSH_SETUP_TIMEOUT, route_transport_plan},
};

const MAX_TICKET_FRAME: usize = 8 * 1024;

struct TunnelOffer {
    ticket: String,
    target_endpoint_id: String,
    route_mode: RouteMode,
    expires_at: u64,
}

pub(super) struct OpenSshSession {
    pub(super) _endpoint: Endpoint,
    pub(super) stream: IrohByteStream,
}

#[derive(Debug, thiserror::Error)]
#[error("SSH access authentication failed: {0}")]
struct SshAuthenticationFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("route network path failed: {0}")]
pub(super) struct RouteNetworkFailure(#[source] anyhow::Error);

#[derive(Debug, thiserror::Error)]
#[error("SSH session failed after activation: {0}")]
struct ActivatedSessionFailure(#[source] anyhow::Error);

pub(super) fn is_retryable_route_failure(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ActivatedSessionFailure>().is_none()
        && error.downcast_ref::<RouteNetworkFailure>().is_some()
}

fn ensure_auth(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(SshAuthenticationFailure(message.to_owned())))
    }
}

pub(super) fn new_attempt_identity() -> (Uuid, SecretKey) {
    (Uuid::new_v4(), SecretKey::generate())
}

pub(super) async fn open_ssh_session(
    context: &ClientContext,
    control: &mut WsStream,
    transport_info: &TransportInfo,
    target_id: Uuid,
    session_id: Uuid,
    secret_key: SecretKey,
    route_mode: RouteMode,
    route_deadline: tokio::time::Instant,
) -> Result<OpenSshSession> {
    let mut deadline = std::cmp::min(
        route_deadline,
        tokio::time::Instant::now() + SSH_SETUP_TIMEOUT,
    );
    let route_transport = route_transport_plan(route_mode, transport_info, context.api.issuer())?;
    let client_endpoint_id = secret_key.public().to_string();
    send_setup_control(
        control,
        &ControlMessage::Open {
            session_id,
            target_id,
            client_endpoint_id: client_endpoint_id.clone(),
            route_mode,
        },
        route_mode,
        deadline,
    )
    .await?;
    let offer = tokio::time::timeout_at(
        deadline,
        next_offer(
            control,
            session_id,
            target_id,
            &client_endpoint_id,
            context.api.issuer(),
            route_mode,
        ),
    )
    .await
    .map_err(|_| route_network_timeout(route_mode, "waiting for target Iroh offer"))??;
    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    let ticket_remaining = offer.expires_at.saturating_sub(wall_now);
    ensure_auth(ticket_remaining > 0, "ticket expired before Iroh setup")?;
    deadline = std::cmp::min(
        deadline,
        tokio::time::Instant::now() + Duration::from_secs(ticket_remaining),
    );
    anyhow::ensure!(
        offer.route_mode == route_mode,
        "offer relay mode differs from request"
    );

    let client_id = secret_key.public();
    let target_id_data = offer
        .target_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| {
            anyhow!(SshAuthenticationFailure(
                "ticket target EndpointId is invalid".to_owned()
            ))
        })?;
    let (handoff, punch_selection) = if let Some(qad_plan) = route_transport.qad_plan.as_ref() {
        let discovery_deadline = std::cmp::min(
            deadline,
            tokio::time::Instant::now() + Duration::from_secs(2),
        );
        let discovery = tokio::select! {
            biased;
            control_message = next_client_session_message(control, session_id, route_mode, deadline) => {
                match control_message? {
                    None => bail!("server closed SSH session during QAD discovery"),
                    Some(_) => bail!("server sent a control message before client QAD discovery completed"),
                }
            }
            result = discover_ipv4_mappings(qad_plan, &context.config.tls, discovery_deadline) => {
                result.map_err(classify_transport_error)?
            }
        };
        let (discovery_message, mut discovered) = match discovery {
            MappingDiscovery::Ready(discovered) => (
                DiscoveryResult::Ready {
                    local_socket: discovered.local_socket,
                    observations: discovered.observations.clone(),
                },
                Some(discovered),
            ),
            MappingDiscovery::Unavailable { reason } => {
                (DiscoveryResult::Unavailable { reason }, None)
            }
        };
        let standard_handoff = discovered
            .as_ref()
            .map(DiscoveredUdpSocket::handoff_options);
        send_setup_control(
            control,
            &ControlMessage::CandidatesReady {
                session_id,
                route_mode,
                discovery: discovery_message,
            },
            route_mode,
            deadline,
        )
        .await?;
        let first_plan = next_client_session_message(control, session_id, route_mode, deadline)
            .await?
            .context("server closed SSH session before native transport plan")?;
        match first_plan {
            ControlMessage::ContinueNative {
                session_id: received,
                route_mode: mode,
                plan: NativePlan::Standard,
            } if received == session_id && mode == route_mode => {
                drop(discovered.take());
                (standard_handoff, None)
            }
            ControlMessage::PunchPair {
                session_id: received,
                route_mode: mode,
                target_endpoint_id,
                client_endpoint_id: paired_client_id,
                peer_discovery,
            } if received == session_id && mode == route_mode => {
                ensure_auth(
                    target_endpoint_id == offer.target_endpoint_id,
                    "server paired a different target data EndpointId",
                )?;
                ensure_auth(
                    paired_client_id == client_endpoint_id,
                    "server paired a different client data EndpointId",
                )?;
                let discovered = discovered.take().context(
                    "server requested direct punching without successful client QAD discovery",
                )?;
                run_client_punch(
                    discovered,
                    standard_handoff.expect("ready QAD discovery includes its direct tuple"),
                    peer_discovery,
                    session_id,
                    target_id_data,
                    client_id,
                    secret_key.clone(),
                    control,
                    route_mode,
                    deadline,
                )
                .await?
            }
            _ => bail!("server returned an unexpected response to client QAD candidates"),
        }
    } else {
        match next_client_session_message(control, session_id, route_mode, deadline)
            .await?
            .context("server closed SSH session before private relay setup")?
        {
            ControlMessage::ContinueNative {
                session_id: received,
                route_mode: mode,
                plan: NativePlan::Standard,
            } if received == session_id && mode == route_mode => (None, None),
            _ => bail!("server returned an unexpected response before private relay setup"),
        }
    };

    if let Some(selection) = &punch_selection {
        tracing::debug!(
            session = %session_id,
            index = selection.index,
            local_socket = %selection.local_socket,
            peer_observed_addr = %selection.peer_observed_addr,
            counters = ?selection.counters,
            native_handoff_selected = handoff.is_some(),
            "client observed signed target punch selection"
        );
    }

    let endpoint = tokio::select! {
        biased;
        message = next_client_session_message(control, session_id, route_mode, deadline) => {
            match message? {
                None => bail!("server closed SSH session before client native endpoint bind"),
                Some(_) => bail!("server sent a control message before client native endpoint bind completed"),
            }
        }
        result = tokio::time::timeout_at(
            deadline,
            create_endpoint(
                secret_key,
                true,
                IrohEndpointOptions {
                    relay_choice: route_transport.relay_choice.clone(),
                    tls: context.config.tls.clone(),
                    handoff,
                }
            ),
        ) => result
            .map_err(|_| route_network_timeout(route_mode, "binding the client Iroh endpoint"))?
            .map_err(classify_transport_error)
            .context("create per-session client Iroh endpoint")?
    };
    let setup_result = async {
        let mut activated = false;
        wait_setup_step(
            control,
            &endpoint,
            session_id,
            route_mode,
            "waiting for client Iroh endpoint readiness",
            &mut activated,
            async {
                wait_endpoint_ready(&endpoint, &route_transport.relay_choice, deadline)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
            },
            deadline,
        )
        .await?;
        let client_endpoint_addr = endpoint.addr();
        ensure_auth(
            client_endpoint_addr.id.to_string() == client_endpoint_id,
            "client EndpointId differs from the SSH attempt identity",
        )?;
        tracing::debug!(
            session = %session_id,
            route_mode = ?route_mode,
            client_endpoint_id = %client_endpoint_addr.id,
            client_ip_addrs = ?client_endpoint_addr.ip_addrs().copied().collect::<Vec<_>>(),
            "publishing prepared client Iroh candidates"
        );
        send_setup_control(
            control,
            &ControlMessage::ClientReady {
                session_id,
                route_mode,
                client_endpoint_addr,
            },
            route_mode,
            deadline,
        )
        .await?;

        let connection = wait_setup_step(
            control,
            &endpoint,
            session_id,
            route_mode,
            "waiting for target Iroh connection",
            &mut activated,
            async {
                accept_peer(&endpoint)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
            },
            deadline,
        )
        .await?;
        ensure_auth(
            connection.remote_id().to_string() == offer.target_endpoint_id,
            "Iroh peer EndpointId differs from the signed target EndpointId",
        )?;
        let path = wait_setup_step(
            control,
            &endpoint,
            session_id,
            route_mode,
            "waiting for the required Iroh path",
            &mut activated,
            async {
                wait_for_selected_path(&connection, route_mode, deadline)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
            },
            deadline,
        )
        .await?;
        send_setup_control(
            control,
            &ControlMessage::PathReady {
                session_id,
                route_mode,
                path,
            },
            route_mode,
            deadline,
        )
        .await?;
        let mut stream = wait_setup_step(
            control,
            &endpoint,
            session_id,
            route_mode,
            "waiting for target SSH stream",
            &mut activated,
            async {
                IrohByteStream::accept_bi(connection)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
            },
            deadline,
        )
        .await?;
        let received_ticket = wait_setup_step(
            control,
            &endpoint,
            session_id,
            route_mode,
            "waiting for signed SSH ticket",
            &mut activated,
            async { read_ticket(&mut stream).await },
            deadline,
        )
        .await?;
        ensure_auth(
            received_ticket == offer.ticket,
            "Iroh stream ticket differs from the signed client offer",
        )?;
        if !activated {
            tokio::time::timeout_at(deadline, wait_activated(control, session_id, route_mode))
                .await
                .map_err(|_| {
                    private_relay_auth_failure(&endpoint, route_mode).unwrap_or_else(|| {
                        route_network_timeout(route_mode, "waiting for SSH activation")
                    })
                })?
                .map_err(|error| classify_anyhow_network_error(error, route_mode))?;
        }
        Ok::<_, anyhow::Error>(stream)
    }
    .await;

    match setup_result {
        Ok(stream) => Ok(OpenSshSession {
            _endpoint: endpoint,
            stream,
        }),
        Err(error) => {
            if tokio::time::timeout_at(deadline, endpoint.close())
                .await
                .is_err()
            {
                tracing::debug!(session = %session_id, "endpoint cleanup reached the shared setup deadline; endpoint drop will abort remaining SDK tasks");
            }
            Err(error)
        }
    }
}

async fn run_client_punch(
    discovered: DiscoveredUdpSocket,
    standard_handoff: HandoffOptions,
    peer_discovery: crate::protocol::ReadyDiscovery,
    session_id: Uuid,
    target_data_id: iroh::EndpointId,
    client_id: iroh::EndpointId,
    secret_key: SecretKey,
    control: &mut WsStream,
    route_mode: RouteMode,
    deadline: tokio::time::Instant,
) -> Result<(
    Option<HandoffOptions>,
    Option<crate::transport::PunchSelection>,
)> {
    let mut punch = match PreparedPunch::prepare(
        PunchRole::Client,
        PunchIdentity {
            session_id,
            target_id: target_data_id,
            client_id,
        },
        secret_key,
        discovered,
        peer_discovery.local_socket,
        peer_discovery.observations,
    ) {
        Ok(punch) => punch,
        Err(PunchError::Unavailable(reason)) => {
            return if report_punch_failure(control, session_id, route_mode, reason, deadline)
                .await?
            {
                Ok((Some(standard_handoff), None))
            } else {
                bail!("server closed SSH session after client punch preparation failed")
            };
        }
        Err(PunchError::Fatal(error)) => {
            return Err(classify_transport_error(error));
        }
    };

    match drive_client_punch(&mut punch, session_id, control, route_mode, deadline).await {
        Err(error) => {
            if let Err(cleanup_error) = punch.finish(false).await {
                return Err(error).context(format!("raw punch cleanup failed: {cleanup_error}"));
            }
            Err(error)
        }
        Ok(ClientPunchOutcome::Standard { selection }) => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            Ok((Some(standard_handoff), selection))
        }
        Ok(ClientPunchOutcome::Selected {
            selection,
            self_observed_addr,
            peer_observed_addr,
        }) => {
            if peer_observed_addr != selection.peer_observed_addr {
                punch.finish(false).await.map_err(anyhow::Error::new)?;
                return Err(anyhow!(SshAuthenticationFailure(
                    "server handoff peer tuple differs from the confirmed client punch winner"
                        .to_owned()
                )));
            }
            let local = punch
                .finish(true)
                .await
                .map_err(anyhow::Error::new)?
                .context("selected client punch did not return a local handoff tuple")?;
            ensure_auth(
                local.index == selection.index && local.bind_addr == selection.local_socket,
                "client punch handoff tuple differs from the selected raw socket",
            )?;
            Ok((
                Some(HandoffOptions {
                    bind_addr: local.bind_addr,
                    self_observed_addr,
                }),
                Some(selection),
            ))
        }
    }
}

enum ClientPunchOutcome {
    Standard {
        selection: Option<crate::transport::PunchSelection>,
    },
    Selected {
        selection: crate::transport::PunchSelection,
        self_observed_addr: std::net::SocketAddrV4,
        peer_observed_addr: std::net::SocketAddrV4,
    },
}

async fn drive_client_punch(
    punch: &mut PreparedPunch,
    session_id: Uuid,
    control: &mut WsStream,
    route_mode: RouteMode,
    deadline: tokio::time::Instant,
) -> Result<ClientPunchOutcome> {
    let socket_count = u16::try_from(punch.socket_count())
        .map_err(|_| anyhow!("client punch socket count exceeds protocol limit"))?;
    send_setup_control(
        control,
        &ControlMessage::PunchReady {
            session_id,
            route_mode,
            socket_count,
        },
        route_mode,
        deadline,
    )
    .await?;
    match next_client_session_message(control, session_id, route_mode, deadline).await? {
        Some(ControlMessage::StartPunch {
            session_id: received,
            route_mode: mode,
        }) if received == session_id && mode == route_mode => {}
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == route_mode => {
            return Ok(ClientPunchOutcome::Standard { selection: None });
        }
        None => {
            bail!("server closed SSH session before client punching started");
        }
        Some(_) => {
            return Err(anyhow!(SshAuthenticationFailure(
                "server sent an unexpected client punch-stage control message".to_owned()
            )));
        }
    }

    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let punch_window = remaining.min(DIRECT_PUNCH_TIMEOUT);
    if punch_window.is_zero() {
        return if report_punch_failure(
            control,
            session_id,
            route_mode,
            "remaining session time is reserved for native relay setup".to_owned(),
            deadline,
        )
        .await?
        {
            Ok(ClientPunchOutcome::Standard { selection: None })
        } else {
            bail!("server closed SSH session after the punch window expired")
        };
    }
    let punch_deadline = tokio::time::Instant::now() + punch_window;
    let selection = tokio::select! {
        biased;
        message = next_client_session_message(control, session_id, route_mode, deadline) => {
            match message? {
                None => {
                    bail!("server closed SSH session during client punching");
                }
                Some(ControlMessage::ContinueNative {
                    session_id: received,
                    route_mode: mode,
                    plan: NativePlan::Standard,
                }) if received == session_id && mode == route_mode => {
                    return Ok(ClientPunchOutcome::Standard { selection: None });
                }
                Some(_) => {
                    return Err(anyhow!(SshAuthenticationFailure(
                        "server sent an unexpected control message while client punching".to_owned()
                    )));
                }
            }
        }
        result = punch.start(punch_deadline) => match result {
            Ok(selection) => selection,
            Err(PunchError::Unavailable(reason)) => {
                return if report_punch_failure(control, session_id, route_mode, reason, deadline).await? {
                    Ok(ClientPunchOutcome::Standard { selection: None })
                } else {
                    bail!("server closed SSH session after client punch failure")
                };
            }
            Err(PunchError::Fatal(error)) => {
                return Err(classify_transport_error(error));
            }
        }
    };

    send_setup_control(
        control,
        &ControlMessage::PunchSelected {
            session_id,
            route_mode,
            index: selection.index,
            local_socket: selection.local_socket,
            peer_observed_addr: selection.peer_observed_addr,
        },
        route_mode,
        deadline,
    )
    .await?;
    match next_client_session_message(control, session_id, route_mode, deadline).await? {
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan:
                NativePlan::Handoff {
                    self_observed_addr,
                    peer_observed_addr,
                },
        }) if received == session_id && mode == route_mode => Ok(ClientPunchOutcome::Selected {
            selection,
            self_observed_addr,
            peer_observed_addr,
        }),
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == route_mode => Ok(ClientPunchOutcome::Standard {
            selection: Some(selection),
        }),
        None => {
            bail!("server closed SSH session before client native handoff")
        }
        Some(_) => Err(anyhow!(SshAuthenticationFailure(
            "server sent an unexpected client native handoff control message".to_owned()
        ))),
    }
}

async fn send_setup_control(
    control: &mut WsStream,
    message: &ControlMessage,
    route_mode: RouteMode,
    deadline: tokio::time::Instant,
) -> Result<()> {
    tokio::time::timeout_at(deadline, Api::send_control(control, message))
        .await
        .map_err(|_| route_network_timeout(route_mode, "sending SSH setup control"))?
        .map_err(|error| classify_anyhow_network_error(error, route_mode))
}

async fn report_punch_failure(
    control: &mut WsStream,
    session_id: Uuid,
    route_mode: RouteMode,
    reason: String,
    deadline: tokio::time::Instant,
) -> Result<bool> {
    send_setup_control(
        control,
        &ControlMessage::PunchFailed {
            session_id,
            route_mode,
            reason,
        },
        route_mode,
        deadline,
    )
    .await?;
    match next_client_session_message(control, session_id, route_mode, deadline).await? {
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == route_mode => Ok(true),
        None => Ok(false),
        Some(_) => Err(anyhow!(SshAuthenticationFailure(
            "server sent a nonstandard native plan after punch failure".to_owned()
        ))),
    }
}

async fn next_client_session_message(
    control: &mut WsStream,
    session_id: Uuid,
    route_mode: RouteMode,
    deadline: tokio::time::Instant,
) -> Result<Option<ControlMessage>> {
    loop {
        let message = tokio::time::timeout_at(deadline, control.next())
            .await
            .map_err(|_| route_network_timeout(route_mode, "waiting for SSH setup control"))?;
        let Some(message) = message else {
            return Err(classify_anyhow_network_error(
                anyhow::Error::new(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control WebSocket ended during SSH setup",
                )),
                route_mode,
            ));
        };
        let message =
            message.map_err(|error| classify_anyhow_network_error(error.into(), route_mode))?;
        if matches!(message, Message::Ping(_) | Message::Pong(_)) {
            continue;
        }
        if matches!(message, Message::Close(_)) {
            return Err(classify_anyhow_network_error(
                anyhow::Error::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "control WebSocket closed during SSH setup",
                )),
                route_mode,
            ));
        }
        let message = Api::control_message(message)?;
        match message {
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
                ..
            } if received == session_id => return Ok(None),
            message => {
                ensure_auth(
                    client_message_session_id(&message) == Some(session_id),
                    "server control message belongs to a different SSH session",
                )?;
                return Ok(Some(message));
            }
        }
    }
}

fn client_message_session_id(message: &ControlMessage) -> Option<Uuid> {
    match message {
        ControlMessage::Open { session_id, .. }
        | ControlMessage::ClientOffer { session_id, .. }
        | ControlMessage::Prepare { session_id, .. }
        | ControlMessage::AgentIdentity { session_id, .. }
        | ControlMessage::IdentityAccepted { session_id, .. }
        | ControlMessage::CandidatesReady { session_id, .. }
        | ControlMessage::PunchPair { session_id, .. }
        | ControlMessage::PunchReady { session_id, .. }
        | ControlMessage::StartPunch { session_id, .. }
        | ControlMessage::PunchSelected { session_id, .. }
        | ControlMessage::PunchFailed { session_id, .. }
        | ControlMessage::ContinueNative { session_id, .. }
        | ControlMessage::PathReady { session_id, .. }
        | ControlMessage::AgentReady { session_id, .. }
        | ControlMessage::ClientReady { session_id, .. }
        | ControlMessage::DialOffer { session_id, .. }
        | ControlMessage::IrohReady { session_id, .. }
        | ControlMessage::Activated { session_id }
        | ControlMessage::Close { session_id, .. } => Some(*session_id),
        ControlMessage::Error { session_id, .. } => *session_id,
    }
}

async fn wait_setup_step<T>(
    control: &mut WsStream,
    endpoint: &Endpoint,
    session_id: Uuid,
    route_mode: RouteMode,
    stage: &'static str,
    activated: &mut bool,
    operation: impl Future<Output = Result<T>>,
    deadline: tokio::time::Instant,
) -> Result<T> {
    let mut operation = Box::pin(operation);
    let wait = async {
        loop {
            tokio::select! {
                biased;
                message = control.next() => {
                    let message = message
                        .context("control WebSocket ended during SSH setup")
                        .and_then(|message| message.context("read control WebSocket during SSH setup"))
                        .map_err(|error| classify_anyhow_network_error(error, route_mode))?;
                    if matches!(message, Message::Ping(_) | Message::Pong(_)) {
                        continue;
                    }
                    match Api::control_message(message)? {
                        ControlMessage::Activated { session_id: received } if received == session_id => {
                            *activated = true;
                        }
                        ControlMessage::Error { session_id: Some(received), code, message }
                            if received == session_id => {
                                let error = server_setup_error(code, message);
                                return Err(if *activated {
                                    anyhow::Error::new(ActivatedSessionFailure(error))
                                } else {
                                    error
                                });
                            }
                        ControlMessage::Error { session_id: None, code, message } => {
                            let error = server_setup_error(code, message);
                            return Err(if *activated {
                                anyhow::Error::new(ActivatedSessionFailure(error))
                            } else {
                                error
                            });
                        }
                        ControlMessage::Close { session_id: received, reason }
                            if received == session_id => bail!("server closed SSH session during setup: {reason}"),
                        _ => tracing::debug!(session = %session_id, "ignoring unexpected control message during Iroh setup"),
                    }
                }
                result = &mut operation => {
                    return result.map_err(|error| {
                        if *activated {
                            anyhow::Error::new(ActivatedSessionFailure(error))
                        } else {
                            classify_anyhow_network_error(error, route_mode)
                        }
                    });
                }
            }
        }
    };
    tokio::time::timeout_at(deadline, wait).await.map_err(|_| {
        private_relay_auth_failure(endpoint, route_mode)
            .unwrap_or_else(|| route_network_timeout(route_mode, stage))
    })?
}

fn classify_transport_error(error: TransportError) -> anyhow::Error {
    if error.is_network_failure() {
        anyhow::Error::new(RouteNetworkFailure(anyhow::Error::new(error)))
    } else {
        anyhow::Error::new(error)
    }
}

fn classify_client_transport_error(
    endpoint: &Endpoint,
    error: TransportError,
    route_mode: RouteMode,
) -> anyhow::Error {
    if let Some(error) = private_relay_auth_failure(endpoint, route_mode) {
        error
    } else {
        classify_transport_error(error)
    }
}

fn private_relay_auth_failure(endpoint: &Endpoint, route_mode: RouteMode) -> Option<anyhow::Error> {
    if route_mode != RouteMode::PrivateRelay {
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

fn server_setup_error(code: String, message: String) -> anyhow::Error {
    match code.as_str() {
        "authentication" | "authorization" => {
            anyhow!(SshAuthenticationFailure(message))
        }
        "network" => anyhow::Error::new(RouteNetworkFailure(anyhow!(message))),
        _ => anyhow!("server could not prepare SSH access: {message}"),
    }
}

fn classify_anyhow_network_error(error: anyhow::Error, _route_mode: RouteMode) -> anyhow::Error {
    if error
        .chain()
        .any(crate::transport::is_network_failure_source)
    {
        anyhow::Error::new(RouteNetworkFailure(error))
    } else {
        error
    }
}

fn route_network_timeout(route_mode: RouteMode, stage: &'static str) -> anyhow::Error {
    let error = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{stage} timed out"),
    ));
    classify_anyhow_network_error(error, route_mode)
}

async fn next_offer(
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

async fn wait_activated(
    control: &mut WsStream,
    session_id: Uuid,
    route_mode: RouteMode,
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
                bail!("server closed SSH session before activation: {reason}");
            }
            _ => {
                tracing::debug!(session = %session_id, "ignoring unexpected control message before activation")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{RouteMode, TunnelTicketClaims},
        transport::{TransportError, connect_peer},
    };
    use iroh::{Endpoint, SecretKey, endpoint::presets};
    use std::io;
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
    fn route_retries_use_a_fresh_session_and_endpoint_key() {
        let attempts = (0..3).map(|_| new_attempt_identity()).collect::<Vec<_>>();
        for left in 0..attempts.len() {
            for right in left + 1..attempts.len() {
                assert_ne!(attempts[left].0, attempts[right].0);
                assert_ne!(attempts[left].1.public(), attempts[right].1.public());
            }
        }
    }

    #[test]
    fn network_failures_advance_routes_but_auth_and_configuration_fail_fast() {
        let private_network = classify_transport_error(TransportError::Network(io::Error::from(
            io::ErrorKind::ConnectionRefused,
        )));
        assert!(
            private_network
                .downcast_ref::<RouteNetworkFailure>()
                .is_some()
        );

        let public_network =
            classify_transport_error(TransportError::Timeout("public direct path"));
        assert!(
            public_network
                .downcast_ref::<RouteNetworkFailure>()
                .is_some()
        );

        let relay_network = classify_transport_error(TransportError::Timeout("private relay"));
        assert!(
            relay_network
                .downcast_ref::<RouteNetworkFailure>()
                .is_some()
        );
        let active_network = anyhow::Error::new(ActivatedSessionFailure(anyhow::Error::new(
            RouteNetworkFailure(anyhow!("transport closed after activation")),
        )));
        assert!(!is_retryable_route_failure(&active_network));

        let private_auth =
            classify_transport_error(TransportError::Authentication("denied".to_owned()));
        assert!(private_auth.downcast_ref::<RouteNetworkFailure>().is_none());
        let private_tls =
            classify_transport_error(TransportError::Tls("certificate rejected".to_owned()));
        assert!(private_tls.downcast_ref::<RouteNetworkFailure>().is_none());
        let private_protocol = classify_transport_error(TransportError::ProtocolViolation(
            "wrong session identity".to_owned(),
        ));
        assert!(
            private_protocol
                .downcast_ref::<RouteNetworkFailure>()
                .is_none()
        );

        let server_auth =
            server_setup_error("authorization".to_owned(), "access denied".to_owned());
        assert!(server_auth.downcast_ref::<RouteNetworkFailure>().is_none());
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
