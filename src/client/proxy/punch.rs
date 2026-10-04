use anyhow::{Context, Result, anyhow, bail};
use iroh::SecretKey;
use uuid::Uuid;

use crate::{
    protocol::{ControlMessage, NativePlan, ReadyDiscovery, RouteMode},
    transport::{
        DiscoveredUdpSocket, HandoffOptions, PreparedPunch, PunchError, PunchIdentity, PunchRole,
        PunchSelection,
    },
};

use super::super::route::DIRECT_PUNCH_TIMEOUT;
use super::{
    SshAuthenticationFailure, WsStream,
    attempt::{classify_transport_error, next_client_session_message, send_setup_control},
    ensure_auth,
};

pub(super) async fn run_client_punch(
    discovered: DiscoveredUdpSocket,
    standard_handoff: HandoffOptions,
    peer_discovery: ReadyDiscovery,
    session_id: Uuid,
    target_data_id: iroh::EndpointId,
    client_id: iroh::EndpointId,
    secret_key: SecretKey,
    control: &mut WsStream,
    route_mode: RouteMode,
    deadline: tokio::time::Instant,
) -> Result<(Option<HandoffOptions>, Option<PunchSelection>)> {
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
        selection: Option<PunchSelection>,
    },
    Selected {
        selection: PunchSelection,
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
