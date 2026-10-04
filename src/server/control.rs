use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::{ServerState, auth::AuthenticatedUser, db::unix_time};
use crate::protocol::{ControlMessage, NativePlan, RouteMode};

mod http;
mod punch;
mod runtime;
mod tunnel;

#[cfg(test)]
pub(in crate::server) use http::authenticate_agent;
pub(in crate::server) use http::{agent_control, client_control, enroll, transport_info};
use punch::{
    PunchSelection, PunchSide, fail_punch_to_native, register_agent_discovery,
    register_client_discovery, register_punch_ready, register_punch_selection, send_native_plans,
};
pub(crate) use runtime::TunnelRuntime;
pub(in crate::server) use runtime::{
    allow_agent_data_endpoint, close_pending_client_tunnels, unregister_agent,
};
use runtime::{
    close_from_client, close_from_target, close_tunnel, fail_from_client, fail_from_target,
    fail_pending_from_target,
};
pub(in crate::server) use tunnel::open_tunnel;
use tunnel::{
    maybe_activate_tunnel, maybe_send_dial_offer, register_agent_data_endpoint,
    register_agent_identity, register_agent_iroh_ready, register_client_endpoint,
    register_path_ready, send_client_offer,
};

pub(super) const MAX_CONTROL_MESSAGE: usize = 64 * 1024;

#[derive(Clone)]
pub struct OnlineAgent {
    pub(crate) connection_id: Uuid,
    pub(crate) sender: mpsc::Sender<ControlMessage>,
}

async fn run_client_control(state: ServerState, user: AuthenticatedUser, socket: WebSocket) {
    let (sender, receiver) = mpsc::channel(64);
    let (mut sink, mut stream) = socket.split();
    let last_pong = Arc::new(AtomicI64::new(unix_time()));
    let writer_last_pong = last_pong.clone();
    let mut writer = tokio::spawn(async move {
        let mut receiver = receiver;
        let mut ticker = tokio::time::interval(Duration::from_secs(20));
        ticker.tick().await;
        loop {
            tokio::select! {
                message = receiver.recv() => {
                    let Some(message) = message else { break; };
                    let Ok(text) = serde_json::to_string(&message) else { break; };
                    if sink.send(Message::Text(text.into())).await.is_err() { break; }
                }
                _ = ticker.tick() => {
                    if unix_time() - writer_last_pong.load(Ordering::Relaxed) > 60 {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    if sink.send(Message::Ping(bytes::Bytes::new())).await.is_err() { break; }
                }
            }
        }
    });
    loop {
        tokio::select! {
            message = stream.next() => match message {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<ControlMessage>(text.as_str()) {
                    Ok(message) => handle_client_message(&state, user, &sender, message).await,
                    Err(_) => send_error(&sender, None, "invalid_message", "invalid control message").await,
                },
                Some(Ok(Message::Pong(_))) => { last_pong.store(unix_time(), Ordering::Relaxed); }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Binary(_))) => {}
            },
            _ = &mut writer => break,
        }
    }
    writer.abort();
    close_pending_client_tunnels(&state, &sender).await;
}

async fn run_agent_control(state: ServerState, target_id: Uuid, socket: WebSocket) {
    let connection_id = Uuid::new_v4();
    let (sender, mut receiver) = mpsc::channel(64);
    {
        let mut online = state.inner.online_agents.write().await;
        if online.contains_key(&target_id) {
            drop(online);
            let mut socket = socket;
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
        online.insert(
            target_id,
            OnlineAgent {
                connection_id,
                sender,
            },
        );
    }
    let (mut sink, mut stream) = socket.split();
    let last_pong = Arc::new(AtomicI64::new(unix_time()));
    let writer_last_pong = last_pong.clone();
    let mut writer = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(20));
        ticker.tick().await;
        loop {
            tokio::select! {
                message = receiver.recv() => {
                    let Some(message) = message else { break; };
                    let Ok(text) = serde_json::to_string(&message) else { break; };
                    if sink.send(Message::Text(text.into())).await.is_err() { break; }
                }
                _ = ticker.tick() => {
                    if unix_time() - writer_last_pong.load(Ordering::Relaxed) > 60 {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    if sink.send(Message::Ping(bytes::Bytes::new())).await.is_err() { break; }
                }
            }
        }
    });
    loop {
        tokio::select! {
            message = stream.next() => match message {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<ControlMessage>(text.as_str()) {
                    Ok(message) => handle_agent_message(&state, target_id, connection_id, message).await,
                    Err(_) => send_agent_error(&state, target_id, connection_id, None, "invalid_message", "invalid control message").await,
                },
                Some(Ok(Message::Pong(_))) => { last_pong.store(unix_time(), Ordering::Relaxed); }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Binary(_))) => {}
            },
            _ = &mut writer => break,
        }
    }
    writer.abort();
    unregister_agent(&state, target_id, connection_id).await;
}

pub(super) async fn handle_client_message(
    state: &ServerState,
    user: AuthenticatedUser,
    sender: &mpsc::Sender<ControlMessage>,
    message: ControlMessage,
) {
    match message {
        ControlMessage::Open {
            session_id,
            target_id,
            client_endpoint_id,
            route_mode,
        } => {
            if let Err(error) = open_tunnel(
                state,
                user,
                sender,
                session_id,
                target_id,
                client_endpoint_id,
                route_mode,
            )
            .await
            {
                send_error(sender, Some(session_id), "open_denied", &error.to_string()).await;
            }
        }
        ControlMessage::Close { session_id, reason } if reason.len() <= 512 => {
            close_from_client(state, session_id, user).await;
        }
        ControlMessage::CandidatesReady {
            session_id,
            route_mode,
            discovery,
        } => {
            if let Err(error) =
                register_client_discovery(state, user, sender, session_id, route_mode, discovery)
                    .await
            {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_discovery_rejected",
                    &error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::PunchReady {
            session_id,
            route_mode,
            socket_count,
        } => {
            if let Err(error) = register_punch_ready(
                state,
                PunchSide::Client,
                session_id,
                route_mode,
                socket_count,
                Some((user, sender)),
                None,
            )
            .await
            {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_punch_rejected",
                    &error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::PunchSelected {
            session_id,
            route_mode,
            index,
            local_socket,
            peer_observed_addr,
        } => {
            if let Err(error) = register_punch_selection(
                state,
                PunchSide::Client,
                session_id,
                route_mode,
                PunchSelection {
                    index,
                    local_socket,
                    peer_observed_addr,
                },
                Some((user, sender)),
                None,
            )
            .await
            {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_punch_rejected",
                    &error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::PunchFailed {
            session_id,
            route_mode,
            reason,
        } => {
            if reason.len() > 512 {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_punch_rejected",
                    "punch failure reason is too long",
                )
                .await;
            } else if let Err(error) = fail_punch_to_native(
                state,
                PunchSide::Client,
                session_id,
                route_mode,
                Some((user, sender)),
                None,
                &reason,
            )
            .await
            {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_punch_rejected",
                    &error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::Error {
            session_id: Some(session_id),
            code,
            message,
        } => {
            let (code, message) = if code.len() <= 128 && message.len() <= 1024 {
                (code, message)
            } else {
                (
                    "invalid_error".to_owned(),
                    "client error report exceeds the control protocol limit".to_owned(),
                )
            };
            fail_from_client(state, user, sender, session_id, &code, &message).await;
        }
        ControlMessage::ClientReady {
            session_id,
            route_mode,
            client_endpoint_addr,
        } => {
            if let Err(error) = register_client_endpoint(
                state,
                user,
                sender,
                session_id,
                route_mode,
                client_endpoint_addr,
            )
            .await
            {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_ready_denied",
                    &error.to_string(),
                )
                .await;
                return;
            }
            let runtime = { state.inner.tunnels.read().await.get(&session_id).cloned() };
            if let Some(runtime) = runtime
                && let Err(error) = maybe_send_dial_offer(state, &runtime).await
            {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_ready_denied",
                    &error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::PathReady {
            session_id,
            route_mode,
            path,
        } => match register_path_ready(
            state,
            session_id,
            route_mode,
            path,
            Some((user, sender)),
            None,
        )
        .await
        {
            Ok(runtime) => maybe_activate_tunnel(state, &runtime).await,
            Err(error) => {
                fail_from_client(
                    state,
                    user,
                    sender,
                    session_id,
                    "client_path_rejected",
                    &error.to_string(),
                )
                .await;
            }
        },
        _ => {
            send_error(
                sender,
                None,
                "invalid_direction",
                "message is not valid from a client",
            )
            .await
        }
    }
}

pub(super) async fn handle_agent_message(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    message: ControlMessage,
) {
    match message {
        ControlMessage::AgentIdentity {
            session_id,
            route_mode,
            target_data_endpoint_id,
            signature,
        } => {
            if let Err(error) = register_agent_identity(
                state,
                target_id,
                connection_id,
                session_id,
                route_mode,
                target_data_endpoint_id,
                signature,
            )
            .await
            {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_identity_rejected".to_owned(),
                    error.to_string(),
                )
                .await;
                return;
            }
            let runtime = { state.inner.tunnels.read().await.get(&session_id).cloned() };
            if let Some(runtime) = runtime
                && runtime.target_id == target_id
                && runtime.target_connection_id == connection_id
            {
                if runtime
                    .target_sender
                    .send(ControlMessage::IdentityAccepted {
                        session_id,
                        route_mode,
                    })
                    .await
                    .is_err()
                {
                    close_tunnel(state, &runtime, "target control connection closed").await;
                    return;
                }
                send_client_offer(state, target_id, connection_id, route_mode, session_id).await;
                if route_mode == RouteMode::PrivateRelay
                    && let Err(error) = send_native_plans(
                        state,
                        &runtime,
                        NativePlan::Standard,
                        NativePlan::Standard,
                    )
                    .await
                {
                    fail_pending_from_target(
                        state,
                        session_id,
                        target_id,
                        connection_id,
                        "private_relay_setup_failed".to_owned(),
                        error.to_string(),
                    )
                    .await;
                }
            }
        }
        ControlMessage::CandidatesReady {
            session_id,
            route_mode,
            discovery,
        } => {
            if let Err(error) = register_agent_discovery(
                state,
                target_id,
                connection_id,
                session_id,
                route_mode,
                discovery,
            )
            .await
            {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_discovery_rejected".to_owned(),
                    error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::PunchReady {
            session_id,
            route_mode,
            socket_count,
        } => {
            if let Err(error) = register_punch_ready(
                state,
                PunchSide::Target,
                session_id,
                route_mode,
                socket_count,
                None,
                Some((target_id, connection_id)),
            )
            .await
            {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_punch_rejected".to_owned(),
                    error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::PunchSelected {
            session_id,
            route_mode,
            index,
            local_socket,
            peer_observed_addr,
        } => {
            if let Err(error) = register_punch_selection(
                state,
                PunchSide::Target,
                session_id,
                route_mode,
                PunchSelection {
                    index,
                    local_socket,
                    peer_observed_addr,
                },
                None,
                Some((target_id, connection_id)),
            )
            .await
            {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_punch_rejected".to_owned(),
                    error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::PunchFailed {
            session_id,
            route_mode,
            reason,
        } => {
            if reason.len() > 512 {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_punch_rejected".to_owned(),
                    "punch failure reason is too long".to_owned(),
                )
                .await;
            } else if let Err(error) = fail_punch_to_native(
                state,
                PunchSide::Target,
                session_id,
                route_mode,
                None,
                Some((target_id, connection_id)),
                &reason,
            )
            .await
            {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_punch_rejected".to_owned(),
                    error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::AgentReady {
            session_id,
            route_mode,
            endpoint_addr,
        } => {
            if let Err(error) = register_agent_data_endpoint(
                state,
                target_id,
                connection_id,
                session_id,
                route_mode,
                endpoint_addr.clone(),
            )
            .await
            {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "endpoint_mismatch".to_owned(),
                    error.to_string(),
                )
                .await;
                return;
            }
            let runtime = { state.inner.tunnels.read().await.get(&session_id).cloned() };
            if let Some(runtime) = runtime
                && let Err(error) = maybe_send_dial_offer(state, &runtime).await
            {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_ready_denied".to_owned(),
                    error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::IrohReady {
            session_id,
            client_endpoint_id,
            target_data_endpoint_id,
            route_mode,
        } => {
            match register_agent_iroh_ready(
                state,
                target_id,
                connection_id,
                session_id,
                client_endpoint_id,
                target_data_endpoint_id,
                route_mode,
            )
            .await
            {
                Ok(runtime) => maybe_activate_tunnel(state, &runtime).await,
                Err(error) => {
                    fail_pending_from_target(
                        state,
                        session_id,
                        target_id,
                        connection_id,
                        "agent_path_rejected".to_owned(),
                        error.to_string(),
                    )
                    .await;
                }
            }
        }
        ControlMessage::PathReady {
            session_id,
            route_mode,
            path,
        } => match register_path_ready(
            state,
            session_id,
            route_mode,
            path,
            None,
            Some((target_id, connection_id)),
        )
        .await
        {
            Ok(runtime) => maybe_activate_tunnel(state, &runtime).await,
            Err(error) => {
                fail_pending_from_target(
                    state,
                    session_id,
                    target_id,
                    connection_id,
                    "agent_path_rejected".to_owned(),
                    error.to_string(),
                )
                .await;
            }
        },
        ControlMessage::Close { session_id, reason } if reason.len() <= 512 => {
            close_from_target(state, session_id, target_id, connection_id).await;
        }
        ControlMessage::Error {
            session_id: Some(session_id),
            code,
            message,
        } => {
            fail_from_target(state, session_id, target_id, connection_id, code, message).await;
        }
        _ => {
            send_agent_error(
                state,
                target_id,
                connection_id,
                None,
                "invalid_direction",
                "message is not valid from a target agent",
            )
            .await
        }
    }
}

async fn send_agent_error(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Option<Uuid>,
    code: &str,
    message: &str,
) {
    let sender = state
        .inner
        .online_agents
        .read()
        .await
        .get(&target_id)
        .filter(|agent| agent.connection_id == connection_id)
        .map(|agent| agent.sender.clone());
    if let Some(sender) = sender {
        send_error(&sender, session_id, code, message).await;
    }
}

async fn send_error(
    sender: &mpsc::Sender<ControlMessage>,
    session_id: Option<Uuid>,
    code: &str,
    message: &str,
) {
    let _ = sender
        .send(ControlMessage::Error {
            session_id,
            code: code.to_owned(),
            message: message.to_owned(),
        })
        .await;
}
