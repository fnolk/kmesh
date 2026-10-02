use axum::extract::{
    Query, State,
    ws::{Message, WebSocket, WebSocketUpgrade},
};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};

use crate::protocol::{PeerRole, RelayConnectQuery};

use super::ServerState;
use super::auth::authenticate;
use super::control::{TunnelPhase, TunnelRuntime, authenticate_agent, close_tunnel};
use super::error::ApiError;

const MAX_RELAY_FRAME: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct RelaySlots {
    client: Option<WebSocket>,
    target: Option<WebSocket>,
    paired: bool,
}

pub(crate) async fn connect(
    State(state): State<ServerState>,
    Query(query): Query<RelayConnectQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let runtime = state
        .inner
        .tunnels
        .read()
        .await
        .get(&query.session_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("tunnel session does not exist"))?;
    match query.peer {
        PeerRole::Client => {
            let user = authenticate(&state, &headers).await?;
            if runtime.user_id != user.user_id || runtime.auth_session_id != user.session_id {
                return Err(ApiError::unauthorized());
            }
        }
        PeerRole::Target => {
            let target_id = authenticate_agent(&state, &headers).await?;
            if runtime.target_id != target_id {
                return Err(ApiError::unauthorized());
            }
        }
    }
    let phase = runtime.state.lock().await.phase;
    if !matches!(
        phase,
        TunnelPhase::RelaySelected | TunnelPhase::Active(crate::protocol::SelectedPath::Relay)
    ) {
        return Err(ApiError::conflict("relay path has not been selected"));
    }
    let role = query.peer;
    Ok(ws
        .max_message_size(MAX_RELAY_FRAME)
        .max_frame_size(MAX_RELAY_FRAME)
        .on_upgrade(move |socket| attach(state, runtime, role, socket)))
}

async fn attach(
    state: ServerState,
    runtime: std::sync::Arc<TunnelRuntime>,
    role: PeerRole,
    socket: WebSocket,
) {
    let pair = {
        let mut slots = runtime.relay_slots.lock().await;
        if slots.paired {
            return;
        }
        let slot = match role {
            PeerRole::Client => &mut slots.client,
            PeerRole::Target => &mut slots.target,
        };
        if slot.is_some() {
            return;
        }
        *slot = Some(socket);
        if slots.client.is_some() && slots.target.is_some() {
            slots.paired = true;
            Some((slots.client.take(), slots.target.take()))
        } else {
            None
        }
    };
    let Some((Some(client), Some(target))) = pair else {
        expire_unpaired(&runtime, role).await;
        return;
    };
    bridge_after_activation(&state, &runtime, client, target).await;
    close_tunnel(&state, &runtime, "relay stream closed").await;
}

async fn expire_unpaired(runtime: &std::sync::Arc<TunnelRuntime>, role: PeerRole) {
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    let mut slots = runtime.relay_slots.lock().await;
    if slots.paired {
        return;
    }
    match role {
        PeerRole::Client => {
            if let Some(mut socket) = slots.client.take() {
                let _ = socket.send(Message::Close(None)).await;
            }
        }
        PeerRole::Target => {
            if let Some(mut socket) = slots.target.take() {
                let _ = socket.send(Message::Close(None)).await;
            }
        }
    }
}

async fn bridge_after_activation(
    state: &ServerState,
    runtime: &std::sync::Arc<TunnelRuntime>,
    client: WebSocket,
    target: WebSocket,
) {
    let mut phase_rx = runtime.phase_tx.subscribe();
    loop {
        match *phase_rx.borrow() {
            TunnelPhase::Active(crate::protocol::SelectedPath::Relay) => break,
            TunnelPhase::Active(crate::protocol::SelectedPath::Quic) | TunnelPhase::Closed => {
                return;
            }
            TunnelPhase::Pending | TunnelPhase::RelaySelected => {}
        }
        if phase_rx.changed().await.is_err() {
            return;
        }
    }
    let _ = state;
    let bridge = bridge(client, target);
    tokio::pin!(bridge);
    loop {
        tokio::select! {
            _ = &mut bridge => return,
            changed = phase_rx.changed() => {
                if changed.is_err() || *phase_rx.borrow() == TunnelPhase::Closed {
                    return;
                }
            }
        }
    }
}

async fn bridge(client: WebSocket, target: WebSocket) {
    let (client_sink, client_stream) = client.split();
    let (target_sink, target_stream) = target.split();
    let client_to_target = pipe(client_stream, target_sink);
    let target_to_client = pipe(target_stream, client_sink);
    tokio::pin!(client_to_target);
    tokio::pin!(target_to_client);
    tokio::select! {
        _ = &mut client_to_target => {},
        _ = &mut target_to_client => {},
    }
}

async fn pipe<R, W>(mut reader: R, mut writer: W)
where
    R: futures_util::Stream<Item = Result<Message, axum::Error>> + Unpin,
    W: futures_util::Sink<Message> + Unpin,
{
    let mut saw_fin = false;
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(20));
    keepalive.tick().await;
    loop {
        tokio::select! {
            message = reader.next() => {
                let Some(Ok(message)) = message else {
                    let _ = writer.send(Message::Close(None)).await;
                    return;
                };
                match message {
                    Message::Binary(frame) if valid_relay_frame(&frame) => {
                        let kind = frame[0];
                        if saw_fin && kind != 1 {
                            let _ = writer.send(Message::Close(None)).await;
                            return;
                        }
                        if kind == 1 {
                            if saw_fin {
                                let _ = writer.send(Message::Close(None)).await;
                                return;
                            }
                            saw_fin = true;
                        }
                        if writer.send(Message::Binary(frame)).await.is_err() { return; }
                        if kind == 2 {
                            let _ = writer.send(Message::Close(None)).await;
                            return;
                        }
                    }
                    Message::Binary(_) | Message::Text(_) => {
                        let _ = writer.send(Message::Close(None)).await;
                        return;
                    }
                    Message::Ping(_) | Message::Pong(_) => {}
                    Message::Close(frame) => {
                        let _ = writer.send(Message::Close(frame)).await;
                        return;
                    }
                }
            }
            _ = keepalive.tick() => {
                if writer.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn valid_relay_frame(frame: &[u8]) -> bool {
    if frame.is_empty() || frame.len() > MAX_RELAY_FRAME {
        return false;
    }
    match frame[0] {
        0 => true,
        1 => frame.len() == 1,
        2 => frame.len() <= 1025,
        _ => false,
    }
}
