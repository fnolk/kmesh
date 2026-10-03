use std::{net::SocketAddrV4, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use uuid::Uuid;

use crate::protocol::{ControlMessage, DiscoveryResult, NativePlan, ReadyDiscovery, RouteMode};

use super::runtime::{TunnelPhase, TunnelRuntime, close_tunnel};
use super::{ServerState, auth::AuthenticatedUser, db::unix_time, error::ApiError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PunchStage {
    WaitingCandidates,
    PairSent,
    Punching,
    NativePlanned,
}

#[derive(Clone, Copy)]
pub(super) struct PunchSelection {
    pub(super) index: u16,
    pub(super) local_socket: std::net::SocketAddrV4,
    pub(super) peer_observed_addr: std::net::SocketAddrV4,
}

#[derive(Clone, Copy)]
pub(super) enum PunchSide {
    Target,
    Client,
}

enum DiscoveryAction {
    Native,
    Pair {
        target: ControlMessage,
        client: ControlMessage,
    },
}

pub(super) async fn register_client_discovery(
    state: &ServerState,
    user: AuthenticatedUser,
    sender: &mpsc::Sender<ControlMessage>,
    session_id: Uuid,
    route_mode: RouteMode,
    discovery: DiscoveryResult,
) -> Result<(), ApiError> {
    register_discovery(
        state,
        PunchSide::Client,
        session_id,
        route_mode,
        discovery,
        Some((user, sender)),
        None,
    )
    .await
}

pub(super) async fn register_agent_discovery(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    route_mode: RouteMode,
    discovery: DiscoveryResult,
) -> Result<(), ApiError> {
    register_discovery(
        state,
        PunchSide::Target,
        session_id,
        route_mode,
        discovery,
        None,
        Some((target_id, connection_id)),
    )
    .await
}

async fn register_discovery(
    state: &ServerState,
    side: PunchSide,
    session_id: Uuid,
    route_mode: RouteMode,
    discovery: DiscoveryResult,
    client: Option<(AuthenticatedUser, &mpsc::Sender<ControlMessage>)>,
    target: Option<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    let ready = validate_discovery(discovery)?;
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if runtime.route_mode != route_mode || *runtime.phase.lock().await != TunnelPhase::Pending {
        return Err(ApiError::conflict("SSH session is not pending"));
    }
    if route_mode == RouteMode::PrivateRelay {
        return Err(ApiError::bad_request(
            "private relay route does not use QAD discovery",
        ));
    }
    if runtime.expires_at <= unix_time() || runtime.access_expires_at <= unix_time() {
        return Err(ApiError::unauthorized());
    }
    match side {
        PunchSide::Client => {
            let Some((user, sender)) = client else {
                return Err(ApiError::unauthorized());
            };
            if !runtime.client_sender.same_channel(sender)
                || runtime.user_id != user.user_id
                || runtime.auth_session_id != user.session_id
                || runtime.access_expires_at != user.access_expires_at
            {
                return Err(ApiError::unauthorized());
            }
        }
        PunchSide::Target => {
            let Some((target_id, connection_id)) = target else {
                return Err(ApiError::unauthorized());
            };
            if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
                return Err(ApiError::unauthorized());
            }
        }
    }

    let mut action = None;
    {
        let mut setup = runtime.setup.lock().await;
        if !setup.client_offer_sent || setup.target_data_endpoint_id.is_none() {
            return Err(ApiError::conflict("session identity is not registered"));
        }
        if setup.punch_stage == PunchStage::NativePlanned {
            return Ok(());
        }
        if setup.punch_stage != PunchStage::WaitingCandidates {
            return Err(ApiError::conflict("candidate exchange already advanced"));
        }
        let slot = match side {
            PunchSide::Target => &mut setup.target_discovery,
            PunchSide::Client => &mut setup.client_discovery,
        };
        if slot.is_some() {
            return Err(ApiError::conflict("QAD results already registered"));
        }
        *slot = ready.clone();

        if ready.is_none() {
            setup.punch_stage = PunchStage::NativePlanned;
            action = Some(DiscoveryAction::Native);
        } else if setup.target_discovery.is_some() && setup.client_discovery.is_some() {
            let target_discovery = setup
                .target_discovery
                .clone()
                .expect("target QAD result is present");
            let client_discovery = setup
                .client_discovery
                .clone()
                .expect("client QAD result is present");
            if use_birthday_target(&target_discovery, &client_discovery) {
                setup.punch_stage = PunchStage::PairSent;
                let target_data_endpoint_id = setup
                    .target_data_endpoint_id
                    .clone()
                    .expect("session identity exists before QAD");
                action = Some(DiscoveryAction::Pair {
                    target: ControlMessage::PunchPair {
                        session_id,
                        route_mode,
                        target_endpoint_id: target_data_endpoint_id.clone(),
                        client_endpoint_id: runtime.client_endpoint_id.clone(),
                        peer_discovery: client_discovery,
                    },
                    client: ControlMessage::PunchPair {
                        session_id,
                        route_mode,
                        target_endpoint_id: target_data_endpoint_id,
                        client_endpoint_id: runtime.client_endpoint_id.clone(),
                        peer_discovery: target_discovery,
                    },
                });
            } else {
                setup.punch_stage = PunchStage::NativePlanned;
                action = Some(DiscoveryAction::Native);
            }
        }
    }

    let Some(action) = action else {
        return Ok(());
    };
    match action {
        DiscoveryAction::Native => {
            send_native_plans(state, &runtime, NativePlan::Standard, NativePlan::Standard).await
        }
        DiscoveryAction::Pair { target, client } => {
            if runtime.target_sender.send(target).await.is_err()
                || runtime.client_sender.send(client).await.is_err()
            {
                close_tunnel(
                    state,
                    &runtime,
                    "control connection closed during punch setup",
                )
                .await;
            }
            Ok(())
        }
    }
}

fn validate_discovery(discovery: DiscoveryResult) -> Result<Option<ReadyDiscovery>, ApiError> {
    match discovery {
        DiscoveryResult::Unavailable { reason } => {
            if reason.len() > 512 {
                return Err(ApiError::bad_request("QAD failure reason is too long"));
            }
            Ok(None)
        }
        DiscoveryResult::Ready {
            local_socket,
            observations,
        } => {
            if local_socket.port() == 0 || observations.is_empty() || observations.len() != 2 {
                return Err(ApiError::bad_request("QAD result is invalid"));
            }
            for (index, observation) in observations.iter().enumerate() {
                if observation.local_socket != local_socket
                    || !observation.handshake_confirmed
                    || observation.reflector.addr.port() == 0
                    || observation.observed_addr.port() == 0
                    || observation.udp_tx_datagrams == 0
                    || observation.udp_rx_datagrams == 0
                {
                    return Err(ApiError::bad_request("QAD observation is incomplete"));
                }
                if observations[..index]
                    .iter()
                    .any(|previous| previous.reflector.addr == observation.reflector.addr)
                {
                    return Err(ApiError::bad_request("QAD reflector is duplicated"));
                }
            }
            Ok(Some(ReadyDiscovery {
                local_socket,
                observations,
            }))
        }
    }
}

fn use_birthday_target(target: &ReadyDiscovery, client: &ReadyDiscovery) -> bool {
    let target_has_distinct_mappings =
        target.observations.iter().enumerate().any(|(index, left)| {
            target.observations[index + 1..].iter().any(|right| {
                left.observed_addr.ip() == right.observed_addr.ip()
                    && left
                        .observed_addr
                        .port()
                        .abs_diff(right.observed_addr.port())
                        > 5
            })
        });
    let client_has_fixed_mapping = client.observations.iter().enumerate().any(|(index, left)| {
        client.observations[index + 1..]
            .iter()
            .any(|right| left.observed_addr == right.observed_addr)
    });
    target_has_distinct_mappings && client_has_fixed_mapping
}

pub(super) async fn register_punch_ready(
    state: &ServerState,
    side: PunchSide,
    session_id: Uuid,
    route_mode: RouteMode,
    socket_count: u16,
    client: Option<(AuthenticatedUser, &mpsc::Sender<ControlMessage>)>,
    target: Option<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if runtime.route_mode != route_mode || *runtime.phase.lock().await != TunnelPhase::Pending {
        return Err(ApiError::conflict("SSH session is not pending"));
    }
    if route_mode == RouteMode::PrivateRelay {
        return Err(ApiError::bad_request(
            "private relay route does not use UDP punch sockets",
        ));
    }
    match side {
        PunchSide::Client => {
            let Some((user, sender)) = client else {
                return Err(ApiError::unauthorized());
            };
            if !runtime.client_sender.same_channel(sender)
                || runtime.user_id != user.user_id
                || runtime.auth_session_id != user.session_id
            {
                return Err(ApiError::unauthorized());
            }
        }
        PunchSide::Target => {
            let Some((target_id, connection_id)) = target else {
                return Err(ApiError::unauthorized());
            };
            if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
                return Err(ApiError::unauthorized());
            }
        }
    }
    let start = {
        let mut setup = runtime.setup.lock().await;
        if setup.punch_stage == PunchStage::NativePlanned {
            return Ok(());
        }
        if setup.punch_stage != PunchStage::PairSent {
            return Err(ApiError::conflict("punch pair is not ready"));
        }
        let expected_count = match side {
            PunchSide::Target => 257,
            PunchSide::Client => 1,
        };
        if socket_count != expected_count {
            return Err(ApiError::bad_request("punch socket count is invalid"));
        }
        match side {
            PunchSide::Target if setup.target_punch_ready => {
                return Err(ApiError::conflict(
                    "target punch readiness already received",
                ));
            }
            PunchSide::Target => setup.target_punch_ready = true,
            PunchSide::Client if setup.client_punch_ready => {
                return Err(ApiError::conflict(
                    "client punch readiness already received",
                ));
            }
            PunchSide::Client => setup.client_punch_ready = true,
        }
        if setup.target_punch_ready && setup.client_punch_ready {
            setup.punch_stage = PunchStage::Punching;
            true
        } else {
            false
        }
    };
    if !start {
        return Ok(());
    }
    if runtime
        .target_sender
        .send(ControlMessage::StartPunch {
            session_id,
            route_mode,
        })
        .await
        .is_err()
    {
        close_tunnel(
            state,
            &runtime,
            "target control connection closed before punch",
        )
        .await;
        return Ok(());
    }
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if *runtime.phase.lock().await != TunnelPhase::Pending
            || runtime.setup.lock().await.punch_stage != PunchStage::Punching
        {
            return;
        }
        if runtime
            .client_sender
            .send(ControlMessage::StartPunch {
                session_id,
                route_mode,
            })
            .await
            .is_err()
        {
            close_tunnel(
                &state,
                &runtime,
                "client control connection closed before punch",
            )
            .await;
        }
    });
    Ok(())
}

pub(super) async fn register_punch_selection(
    state: &ServerState,
    side: PunchSide,
    session_id: Uuid,
    route_mode: RouteMode,
    selection: PunchSelection,
    client: Option<(AuthenticatedUser, &mpsc::Sender<ControlMessage>)>,
    target: Option<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if runtime.route_mode != route_mode || *runtime.phase.lock().await != TunnelPhase::Pending {
        return Err(ApiError::conflict("SSH session is not pending"));
    }
    if route_mode == RouteMode::PrivateRelay {
        return Err(ApiError::bad_request(
            "private relay route does not use UDP punch selection",
        ));
    }
    match side {
        PunchSide::Client => {
            let Some((user, sender)) = client else {
                return Err(ApiError::unauthorized());
            };
            if !runtime.client_sender.same_channel(sender)
                || runtime.user_id != user.user_id
                || runtime.auth_session_id != user.session_id
            {
                return Err(ApiError::unauthorized());
            }
        }
        PunchSide::Target => {
            let Some((target_id, connection_id)) = target else {
                return Err(ApiError::unauthorized());
            };
            if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
                return Err(ApiError::unauthorized());
            }
        }
    }
    let plans = {
        let mut setup = runtime.setup.lock().await;
        if setup.punch_stage == PunchStage::NativePlanned {
            return Ok(());
        }
        if setup.punch_stage != PunchStage::Punching {
            return Err(ApiError::conflict("punch has not started"));
        }
        if selection.index >= 257
            || selection.local_socket.port() == 0
            || selection.peer_observed_addr.port() == 0
            || selection.peer_observed_addr.ip().is_unspecified()
        {
            return Err(ApiError::bad_request("selected punch tuple is invalid"));
        }
        match side {
            PunchSide::Target => {
                let Some(discovery) = setup.target_discovery.as_ref() else {
                    return Err(ApiError::conflict("target QAD result is missing"));
                };
                if selection.local_socket.ip() != discovery.local_socket.ip()
                    || (selection.index == 0 && selection.local_socket != discovery.local_socket)
                {
                    return Err(ApiError::bad_request(
                        "target punch socket does not match its QAD-bound address",
                    ));
                }
            }
            PunchSide::Client => {
                let Some(discovery) = setup.client_discovery.as_ref() else {
                    return Err(ApiError::conflict("client QAD result is missing"));
                };
                if selection.local_socket != discovery.local_socket {
                    return Err(ApiError::bad_request(
                        "client punch socket differs from its QAD-bound socket",
                    ));
                }
            }
        }
        let slot = match side {
            PunchSide::Target => &mut setup.target_selection,
            PunchSide::Client => &mut setup.client_selection,
        };
        if slot.is_some() {
            return Err(ApiError::conflict("punch selection already received"));
        }
        *slot = Some(selection);
        let (Some(target_selection), Some(client_selection)) =
            (setup.target_selection, setup.client_selection)
        else {
            return Ok(());
        };
        if target_selection.index != client_selection.index {
            return Err(ApiError::bad_request(
                "target and client selected different punch indexes",
            ));
        }
        setup.punch_stage = PunchStage::NativePlanned;
        (
            NativePlan::Handoff {
                self_observed_addr: client_selection.peer_observed_addr,
                peer_observed_addr: target_selection.peer_observed_addr,
            },
            NativePlan::Handoff {
                self_observed_addr: target_selection.peer_observed_addr,
                peer_observed_addr: client_selection.peer_observed_addr,
            },
        )
    };
    send_native_plans(state, &runtime, plans.0, plans.1).await
}

pub(super) async fn fail_punch_to_native(
    state: &ServerState,
    side: PunchSide,
    session_id: Uuid,
    route_mode: RouteMode,
    client: Option<(AuthenticatedUser, &mpsc::Sender<ControlMessage>)>,
    target: Option<(Uuid, Uuid)>,
    reason: &str,
) -> Result<(), ApiError> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if runtime.route_mode != route_mode || *runtime.phase.lock().await != TunnelPhase::Pending {
        return Err(ApiError::conflict("SSH session is not pending"));
    }
    if route_mode == RouteMode::PrivateRelay {
        return Err(ApiError::bad_request(
            "private relay route does not use UDP punch failure reports",
        ));
    }
    match side {
        PunchSide::Client => {
            let Some((user, sender)) = client else {
                return Err(ApiError::unauthorized());
            };
            if !runtime.client_sender.same_channel(sender)
                || runtime.user_id != user.user_id
                || runtime.auth_session_id != user.session_id
            {
                return Err(ApiError::unauthorized());
            }
        }
        PunchSide::Target => {
            let Some((target_id, connection_id)) = target else {
                return Err(ApiError::unauthorized());
            };
            if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
                return Err(ApiError::unauthorized());
            }
        }
    }
    {
        let mut setup = runtime.setup.lock().await;
        if setup.punch_stage == PunchStage::NativePlanned {
            return Ok(());
        }
        if setup.punch_stage != PunchStage::Punching {
            return Err(ApiError::conflict("punch is not active"));
        }
        setup.punch_stage = PunchStage::NativePlanned;
    }
    tracing::info!(session = %session_id, reason, "raw UDP punch failed; continue with Iroh native transport");
    send_native_plans(state, &runtime, NativePlan::Standard, NativePlan::Standard).await
}

pub(super) async fn send_native_plans(
    state: &ServerState,
    runtime: &Arc<TunnelRuntime>,
    target_plan: NativePlan,
    client_plan: NativePlan,
) -> Result<(), ApiError> {
    let target_message = ControlMessage::ContinueNative {
        session_id: runtime.session_id,
        route_mode: runtime.route_mode,
        plan: target_plan,
    };
    let client_message = ControlMessage::ContinueNative {
        session_id: runtime.session_id,
        route_mode: runtime.route_mode,
        plan: client_plan,
    };
    if runtime.target_sender.send(target_message).await.is_err()
        || runtime.client_sender.send(client_message).await.is_err()
    {
        close_tunnel(
            state,
            runtime,
            "control connection closed during native setup",
        )
        .await;
    }
    Ok(())
}
