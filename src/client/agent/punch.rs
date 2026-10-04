use anyhow::{Context, Result, anyhow};
use iroh::SecretKey;
use tokio::{sync::mpsc, time::Instant};
use uuid::Uuid;

use super::control::next_session_message;
use super::{AgentAuthenticationFailure, ensure_auth};
use crate::client::route::DIRECT_PUNCH_TIMEOUT;
use crate::{
    protocol::{ControlMessage, NativePlan, RouteMode},
    transport::{HandoffOptions, PreparedPunch, PunchError, PunchIdentity, PunchRole},
};

pub(super) async fn run_target_punch(
    session_id: Uuid,
    route_mode: RouteMode,
    target_data_id: iroh::EndpointId,
    client_id: iroh::EndpointId,
    data_key: SecretKey,
    discovered: crate::transport::DiscoveredUdpSocket,
    peer_discovery: crate::protocol::ReadyDiscovery,
    control_rx: &mut mpsc::Receiver<ControlMessage>,
    outbound: &mpsc::Sender<ControlMessage>,
    deadline: Instant,
) -> Result<
    Option<(
        Option<HandoffOptions>,
        Option<crate::transport::PunchSelection>,
    )>,
> {
    let standard_handoff = discovered.handoff_options();
    let mut punch = match PreparedPunch::prepare(
        PunchRole::Target,
        PunchIdentity {
            session_id,
            target_id: target_data_id,
            client_id,
        },
        data_key,
        discovered,
        peer_discovery.local_socket,
        peer_discovery.observations,
    ) {
        Ok(punch) => punch,
        Err(PunchError::Unavailable(reason)) => {
            return if report_target_punch_failure(
                outbound, control_rx, session_id, route_mode, reason, deadline,
            )
            .await?
            {
                Ok(Some((Some(standard_handoff), None)))
            } else {
                Ok(None)
            };
        }
        Err(PunchError::Fatal(error)) => return Err(anyhow::Error::new(error)),
    };

    let socket_count = u16::try_from(punch.socket_count())
        .map_err(|_| anyhow!("target punch socket count exceeds protocol limit"))?;
    outbound
        .send(ControlMessage::PunchReady {
            session_id,
            route_mode,
            socket_count,
        })
        .await
        .context("report target punch socket readiness")?;
    let start = match next_session_message(control_rx, session_id, deadline).await? {
        None => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            return Ok(None);
        }
        Some(ControlMessage::StartPunch {
            session_id: received,
            route_mode: mode,
        }) if received == session_id && mode == route_mode => true,
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == route_mode => false,
        Some(_) => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            return Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected target punch-stage control message".to_owned()
            )));
        }
    };
    if !start {
        punch.finish(false).await.map_err(anyhow::Error::new)?;
        return Ok(Some((Some(standard_handoff), None)));
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    let punch_window = remaining.min(DIRECT_PUNCH_TIMEOUT);
    if punch_window.is_zero() {
        punch.finish(false).await.map_err(anyhow::Error::new)?;
        return if report_target_punch_failure(
            outbound,
            control_rx,
            session_id,
            route_mode,
            "remaining session time is reserved for native relay setup".to_owned(),
            deadline,
        )
        .await?
        {
            Ok(Some((Some(standard_handoff), None)))
        } else {
            Ok(None)
        };
    }
    let punch_deadline = Instant::now() + punch_window;
    let selection = tokio::select! {
        biased;
        control = next_session_message(control_rx, session_id, deadline) => {
            match control? {
                None => {
                    punch.finish(false).await.map_err(anyhow::Error::new)?;
                    return Ok(None);
                }
                Some(ControlMessage::ContinueNative {
                    session_id: received,
                    route_mode: mode,
                    plan: NativePlan::Standard,
                }) if received == session_id && mode == route_mode => {
                    punch.finish(false).await.map_err(anyhow::Error::new)?;
                    return Ok(Some((None, None)));
                }
                Some(_) => {
                    punch.finish(false).await.map_err(anyhow::Error::new)?;
                    return Err(anyhow!(AgentAuthenticationFailure(
                        "server sent an unexpected control event while target punch was active".to_owned()
                    )));
                }
            }
        }
        result = punch.start(punch_deadline) => match result {
            Ok(selection) => selection,
            Err(PunchError::Unavailable(reason)) => {
                punch.finish(false).await.map_err(anyhow::Error::new)?;
                return if report_target_punch_failure(
                    outbound,
                    control_rx,
                    session_id,
                    route_mode,
                    reason,
                    deadline,
                )
                .await?
                {
                    Ok(Some((Some(standard_handoff), None)))
                } else {
                    Ok(None)
                };
            }
            Err(PunchError::Fatal(error)) => {
                punch.finish(false).await.map_err(anyhow::Error::new)?;
                return Err(anyhow::Error::new(error));
            }
        }
    };

    outbound
        .send(ControlMessage::PunchSelected {
            session_id,
            route_mode,
            index: selection.index,
            local_socket: selection.local_socket,
            peer_observed_addr: selection.peer_observed_addr,
        })
        .await
        .context("report target raw UDP winner")?;
    match next_session_message(control_rx, session_id, deadline).await? {
        None => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            Ok(None)
        }
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan:
                NativePlan::Handoff {
                    self_observed_addr,
                    peer_observed_addr,
                },
        }) if received == session_id && mode == route_mode => {
            ensure_auth(
                peer_observed_addr == selection.peer_observed_addr,
                "server handoff peer tuple differs from the confirmed target punch winner",
            )?;
            let local = punch
                .finish(true)
                .await
                .map_err(anyhow::Error::new)?
                .context("selected target punch did not return a local handoff tuple")?;
            ensure_auth(
                local.index == selection.index && local.bind_addr == selection.local_socket,
                "target punch handoff tuple differs from the selected raw socket",
            )?;
            Ok(Some((
                Some(HandoffOptions {
                    bind_addr: local.bind_addr,
                    self_observed_addr,
                }),
                Some(selection),
            )))
        }
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == route_mode => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            Ok(Some((Some(standard_handoff), Some(selection))))
        }
        Some(_) => {
            punch.finish(false).await.map_err(anyhow::Error::new)?;
            Err(anyhow!(AgentAuthenticationFailure(
                "server sent an unexpected target native handoff control message".to_owned()
            )))
        }
    }
}

async fn report_target_punch_failure(
    outbound: &mpsc::Sender<ControlMessage>,
    control_rx: &mut mpsc::Receiver<ControlMessage>,
    session_id: Uuid,
    route_mode: RouteMode,
    reason: String,
    deadline: Instant,
) -> Result<bool> {
    outbound
        .send(ControlMessage::PunchFailed {
            session_id,
            route_mode,
            reason,
        })
        .await
        .context("report target punch network failure")?;
    match next_session_message(control_rx, session_id, deadline).await? {
        Some(ControlMessage::ContinueNative {
            session_id: received,
            route_mode: mode,
            plan: NativePlan::Standard,
        }) if received == session_id && mode == route_mode => Ok(true),
        None => Ok(false),
        Some(_) => Err(anyhow!(AgentAuthenticationFailure(
            "server sent a nonstandard native plan after target punch failure".to_owned()
        ))),
    }
}
