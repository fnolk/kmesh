use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use iroh::{Endpoint, SecretKey, Watcher as _};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::{
    protocol::{ControlMessage, DiscoveryResult, NativePlan, RouteMode, TransportInfo},
    transport::{
        DiscoveredUdpSocket, IrohByteStream, IrohEndpointOptions, MappingDiscovery, PunchIdentity,
        TransportError, accept_peer, create_endpoint, discover_ipv4_mappings,
        is_auth_failure_source, wait_endpoint_ready, wait_for_selected_path,
    },
};

use super::super::{
    ClientContext,
    api::{Api, WsStream},
    route::{SSH_SETUP_TIMEOUT, route_transport_plan},
};
use super::ENDPOINT_CLOSE_BUDGET;
use super::{
    ActivatedSessionFailure, RouteNetworkFailure, SshAuthenticationFailure, ensure_auth, punch,
    server_setup_error, ticket,
};

pub(super) struct OpenSshSession {
    pub(super) endpoint: Endpoint,
    pub(super) stream: IrohByteStream,
}

pub(super) async fn close_endpoint(endpoint: &Endpoint) {
    endpoint.close().await;
}

pub(super) struct SshAttempt<'a> {
    pub(super) client: &'a ClientContext,
    pub(super) transport_info: &'a TransportInfo,
    pub(super) target_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) secret_key: SecretKey,
    pub(super) route_mode: RouteMode,
    pub(super) attempt_deadline: tokio::time::Instant,
    pub(super) setup_deadline: tokio::time::Instant,
}

pub(super) fn new_attempt_identity() -> (Uuid, SecretKey) {
    (Uuid::new_v4(), SecretKey::generate())
}

pub(super) async fn open_ssh_session(
    control: &mut WsStream,
    attempt: SshAttempt<'_>,
) -> Result<OpenSshSession> {
    let SshAttempt {
        client: context,
        transport_info,
        target_id,
        session_id,
        secret_key,
        route_mode,
        attempt_deadline: route_deadline,
        setup_deadline,
    } = attempt;
    let mut deadline = std::cmp::min(
        std::cmp::min(route_deadline, setup_deadline),
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
        ticket::next_offer(
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
        let (discovery, early_native_plan) = wait_for_discovery_or_native_plan(
            control,
            session_id,
            route_mode,
            deadline,
            discover_ipv4_mappings(qad_plan, &context.config.tls, deadline),
        )
        .await?;
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
        let first_plan = match early_native_plan {
            Some(plan) => ControlMessage::ContinueNative {
                session_id,
                route_mode,
                plan,
            },
            None => next_client_session_message(control, session_id, route_mode, deadline)
                .await?
                .context("server closed SSH session before native transport plan")?,
        };
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
                punch::run_client_punch(
                    discovered,
                    standard_handoff.expect("ready QAD discovery includes its direct tuple"),
                    peer_discovery,
                    punch::ClientPunchAttempt {
                        identity: PunchIdentity {
                            session_id,
                            target_id: target_id_data,
                            client_id,
                        },
                        secret_key: secret_key.clone(),
                        route_mode,
                        deadline,
                    },
                    control,
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
        let mut progress = SetupProgress {
            session_id,
            route_mode,
            deadline,
            activated: false,
        };
        wait_setup_step(
            control,
            &endpoint,
            &mut progress,
            "waiting for client Iroh endpoint readiness",
            async {
                wait_endpoint_ready(&endpoint, &route_transport.relay_choice, deadline)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
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
            &mut progress,
            "waiting for target Iroh connection",
            async {
                accept_peer(&endpoint)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
            },
        )
        .await?;
        ensure_auth(
            connection.remote_id().to_string() == offer.target_endpoint_id,
            "Iroh peer EndpointId differs from the signed target EndpointId",
        )?;
        let path = wait_setup_step(
            control,
            &endpoint,
            &mut progress,
            "waiting for the required Iroh path",
            async {
                wait_for_selected_path(&connection, route_mode, deadline)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
            },
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
            &mut progress,
            "waiting for target SSH stream",
            async {
                IrohByteStream::accept_bi(connection)
                    .await
                    .map_err(|error| classify_client_transport_error(&endpoint, error, route_mode))
            },
        )
        .await?;
        let received_ticket = wait_setup_step(
            control,
            &endpoint,
            &mut progress,
            "waiting for signed SSH ticket",
            async { ticket::read_ticket(&mut stream).await },
        )
        .await?;
        ensure_auth(
            received_ticket == offer.ticket,
            "Iroh stream ticket differs from the signed client offer",
        )?;
        if !progress.activated {
            tokio::time::timeout_at(deadline, wait_activated(control, session_id))
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
        Ok(stream) => Ok(OpenSshSession { endpoint, stream }),
        Err(error) => {
            let cleanup_deadline = std::cmp::min(
                setup_deadline,
                tokio::time::Instant::now() + ENDPOINT_CLOSE_BUDGET,
            );
            if tokio::time::timeout_at(cleanup_deadline, close_endpoint(&endpoint))
                .await
                .is_err()
            {
                tracing::warn!(session = %session_id, "endpoint close exceeded the reserved cleanup budget; dropping the endpoint");
            }
            Err(error)
        }
    }
}

async fn wait_for_discovery_or_native_plan(
    control: &mut WsStream,
    session_id: Uuid,
    route_mode: RouteMode,
    setup_deadline: tokio::time::Instant,
    discovery: impl Future<Output = Result<MappingDiscovery, TransportError>> + Send,
) -> Result<(MappingDiscovery, Option<NativePlan>)> {
    let discovery = async {
        match tokio::time::timeout_at(setup_deadline, discovery).await {
            Ok(result) => result.map_err(classify_transport_error),
            Err(_) => Ok(MappingDiscovery::Unavailable {
                reason: "QAD discovery and cleanup exceeded the SSH setup deadline".to_owned(),
            }),
        }
    };
    tokio::pin!(discovery);
    let mut early_native_plan = None;
    loop {
        tokio::select! {
            biased;
            message = next_client_session_message(control, session_id, route_mode, setup_deadline) => {
                match message? {
                    Some(ControlMessage::ContinueNative {
                        session_id: received,
                        route_mode: mode,
                        plan: NativePlan::Standard,
                    }) if received == session_id && mode == route_mode && early_native_plan.is_none() => {
                        early_native_plan = Some(NativePlan::Standard);
                    }
                    None => bail!("server closed SSH session during QAD discovery"),
                    Some(_) => bail!("server sent a control message before client QAD discovery completed"),
                }
            }
            result = &mut discovery => return Ok((result?, early_native_plan)),
        }
    }
}

pub(super) async fn send_setup_control(
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

pub(super) async fn next_client_session_message(
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

struct SetupProgress {
    session_id: Uuid,
    route_mode: RouteMode,
    deadline: tokio::time::Instant,
    activated: bool,
}

async fn wait_setup_step<T>(
    control: &mut WsStream,
    endpoint: &Endpoint,
    progress: &mut SetupProgress,
    stage: &'static str,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    let session_id = progress.session_id;
    let route_mode = progress.route_mode;
    let deadline = progress.deadline;
    let activated = &mut progress.activated;
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

pub(super) fn classify_transport_error(error: TransportError) -> anyhow::Error {
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

pub(super) fn classify_anyhow_network_error(
    error: anyhow::Error,
    _route_mode: RouteMode,
) -> anyhow::Error {
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
    use super::super::is_retryable_route_failure;
    use super::*;
    use crate::transport::{BoxedIo, TransportError};
    use anyhow::anyhow;
    use std::io;
    use tokio::sync::oneshot;
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

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

    #[tokio::test]
    async fn early_standard_plan_is_retained_until_bounded_qad_finishes() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client_control: WsStream =
            WebSocketStream::from_raw_socket(Box::new(client_io) as BoxedIo, Role::Client, None)
                .await;
        let mut server_control: WsStream =
            WebSocketStream::from_raw_socket(Box::new(server_io) as BoxedIo, Role::Server, None)
                .await;
        let session_id = Uuid::new_v4();
        let (finish_discovery, discovery_gate) = oneshot::channel();
        let discovery = async move {
            discovery_gate
                .await
                .expect("finish deterministic QAD future");
            Ok(MappingDiscovery::Unavailable {
                reason: "fixture QAD unavailable".to_owned(),
            })
        };
        let discovery_task = tokio::spawn(async move {
            wait_for_discovery_or_native_plan(
                &mut client_control,
                session_id,
                RouteMode::PrivateDirect,
                tokio::time::Instant::now() + Duration::from_secs(2),
                discovery,
            )
            .await
        });

        Api::send_control(
            &mut server_control,
            &ControlMessage::ContinueNative {
                session_id,
                route_mode: RouteMode::PrivateDirect,
                plan: NativePlan::Standard,
            },
        )
        .await
        .expect("deliver early standard plan");
        finish_discovery
            .send(())
            .expect("release deterministic QAD future");

        let (discovery, early_plan) = tokio::time::timeout(Duration::from_secs(2), discovery_task)
            .await
            .expect("QAD and early plan complete within the route deadline")
            .expect("discovery task does not panic")
            .expect("early Standard is a valid route decision");
        assert!(matches!(
            discovery,
            MappingDiscovery::Unavailable { ref reason } if reason == "fixture QAD unavailable"
        ));
        assert!(matches!(early_plan, Some(NativePlan::Standard)));
    }

    #[tokio::test]
    async fn server_error_cancels_qad_discovery_immediately() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client_control: WsStream =
            WebSocketStream::from_raw_socket(Box::new(client_io) as BoxedIo, Role::Client, None)
                .await;
        let mut server_control: WsStream =
            WebSocketStream::from_raw_socket(Box::new(server_io) as BoxedIo, Role::Server, None)
                .await;
        let session_id = Uuid::new_v4();
        let (started_tx, started_rx) = oneshot::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let discovery = async move {
            let _ = started_tx.send(());
            let _cancel_rx = cancel_rx;
            std::future::pending::<Result<MappingDiscovery, TransportError>>().await
        };
        let discovery_task = tokio::spawn(async move {
            wait_for_discovery_or_native_plan(
                &mut client_control,
                session_id,
                RouteMode::PrivateDirect,
                tokio::time::Instant::now() + Duration::from_secs(2),
                discovery,
            )
            .await
        });
        started_rx.await.expect("QAD discovery was polled");

        Api::send_control(
            &mut server_control,
            &ControlMessage::ContinueNative {
                session_id,
                route_mode: RouteMode::PrivateDirect,
                plan: NativePlan::Standard,
            },
        )
        .await
        .expect("deliver early standard plan");
        Api::send_control(
            &mut server_control,
            &ControlMessage::Error {
                session_id: Some(session_id),
                code: "authorization".to_owned(),
                message: "target access revoked".to_owned(),
            },
        )
        .await
        .expect("deliver server authorization error");

        let error = tokio::time::timeout(Duration::from_secs(2), discovery_task)
            .await
            .expect("server error stops QAD without waiting for its deadline")
            .expect("discovery task does not panic")
            .expect_err("server authorization error terminates route setup");
        assert!(
            error
                .downcast_ref::<super::super::SshAuthenticationFailure>()
                .is_some(),
            "server authorization remains an authentication boundary error"
        );
        assert!(error.to_string().contains("target access revoked"));
        assert!(
            cancel_tx.send(()).is_err(),
            "QAD future was dropped on error"
        );
    }

    #[tokio::test]
    async fn server_close_cancels_qad_discovery_immediately() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client_control: WsStream =
            WebSocketStream::from_raw_socket(Box::new(client_io) as BoxedIo, Role::Client, None)
                .await;
        let mut server_control: WsStream =
            WebSocketStream::from_raw_socket(Box::new(server_io) as BoxedIo, Role::Server, None)
                .await;
        let session_id = Uuid::new_v4();
        let (started_tx, started_rx) = oneshot::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let discovery = async move {
            let _ = started_tx.send(());
            let _cancel_rx = cancel_rx;
            std::future::pending::<Result<MappingDiscovery, TransportError>>().await
        };
        let discovery_task = tokio::spawn(async move {
            wait_for_discovery_or_native_plan(
                &mut client_control,
                session_id,
                RouteMode::PrivateDirect,
                tokio::time::Instant::now() + Duration::from_secs(2),
                discovery,
            )
            .await
        });
        started_rx.await.expect("QAD discovery was polled");

        Api::send_control(
            &mut server_control,
            &ControlMessage::ContinueNative {
                session_id,
                route_mode: RouteMode::PrivateDirect,
                plan: NativePlan::Standard,
            },
        )
        .await
        .expect("deliver early standard plan");
        Api::send_control(
            &mut server_control,
            &ControlMessage::Close {
                session_id,
                reason: "target disconnected".to_owned(),
            },
        )
        .await
        .expect("deliver server close");

        let error = tokio::time::timeout(Duration::from_secs(2), discovery_task)
            .await
            .expect("server close stops QAD without waiting for its deadline")
            .expect("discovery task does not panic")
            .expect_err("server close terminates route setup");
        assert!(
            error
                .to_string()
                .contains("server closed SSH session during QAD discovery")
        );
        assert!(
            cancel_tx.send(()).is_err(),
            "QAD future was dropped on close"
        );
    }

    #[tokio::test]
    async fn endpoint_close_finishes_before_its_owner_is_dropped() {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![crate::transport::IROH_SSH_ALPN.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind isolated endpoint");

        close_endpoint(&endpoint).await;

        assert!(endpoint.is_closed());
    }
}
