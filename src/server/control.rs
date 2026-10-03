use std::{
    collections::HashMap,
    sync::Arc,
    sync::atomic::{AtomicI64, Ordering},
    time::Duration,
};

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use iroh::EndpointAddr;
use sqlx::Row;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::{
    identity::{self, TUNNEL_TICKET_AUDIENCE},
    protocol::{
        AgentEnrollmentRequest, AgentEnrollmentResponse, ControlMessage, RelayMode,
        TunnelTicketClaims,
    },
};

use super::{
    ServerState,
    auth::{AuthenticatedUser, authenticate, bearer_token},
    db::{row_uuid, unix_time},
    error::ApiError,
    hash_secret,
};

const TICKET_TTL_SECS: i64 = 60;
const MAX_CONTROL_MESSAGE: usize = 64 * 1024;

#[derive(Clone)]
pub struct OnlineAgent {
    pub(crate) connection_id: Uuid,
    pub(crate) sender: mpsc::Sender<ControlMessage>,
    pub(crate) endpoints: HashMap<RelayMode, EndpointAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelPhase {
    Pending,
    Active,
    Closed,
}

pub(crate) struct TunnelRuntime {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub auth_session_id: Uuid,
    pub access_expires_at: i64,
    pub target_id: Uuid,
    pub target_connection_id: Uuid,
    pub relay_mode: RelayMode,
    pub client_endpoint_id: String,
    pub target_endpoint_id: String,
    pub ticket: String,
    pub client_offer_sent: Mutex<bool>,
    pub client_endpoint_addr: Mutex<Option<EndpointAddr>>,
    pub client_sender: mpsc::Sender<ControlMessage>,
    pub target_sender: mpsc::Sender<ControlMessage>,
    pub phase: Mutex<TunnelPhase>,
    pub expires_at: i64,
}

pub(crate) async fn transport_info(
    State(state): State<ServerState>,
) -> axum::Json<crate::protocol::TransportInfo> {
    axum::Json(state.inner.transport_info.read().await.clone())
}

pub(crate) async fn enroll(
    State(state): State<ServerState>,
    axum::Json(request): axum::Json<AgentEnrollmentRequest>,
) -> Result<axum::Json<AgentEnrollmentResponse>, ApiError> {
    if request.enrollment_token.len() > 256 {
        return Err(ApiError::bad_request("enrollment request is too large"));
    }
    let endpoint_id = request
        .agent_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| ApiError::bad_request("agent EndpointId is invalid"))?
        .to_string();
    let token_hash = hash_secret(&request.enrollment_token);
    let now = unix_time();
    let agent_token = super::new_secret();
    let agent_token_hash = hash_secret(&agent_token);
    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let target = sqlx::query(
        "SELECT enrollment_token_hash, enrollment_expires_at, enabled, deleted_at FROM targets WHERE id = ?1",
    )
    .bind(request.target_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    let stored_hash: Option<String> = target.try_get("enrollment_token_hash")?;
    let expires_at: Option<i64> = target.try_get("enrollment_expires_at")?;
    let enabled: i64 = target.try_get("enabled")?;
    let deleted_at: Option<i64> = target.try_get("deleted_at")?;
    if enabled != 1
        || deleted_at.is_some()
        || expires_at.is_none_or(|expiry| expiry <= now)
        || stored_hash.as_deref() != Some(token_hash.as_str())
    {
        return Err(ApiError::unauthorized());
    }
    let changed = sqlx::query(
        "UPDATE targets SET enrollment_token_hash = NULL, enrollment_expires_at = NULL, \
             agent_token_hash = ?1, agent_endpoint_id = ?2, enrolled_at = ?3, updated_at = ?3 \
         WHERE id = ?4 AND enrollment_token_hash = ?5 AND enrollment_expires_at > ?3 AND enabled = 1",
    )
    .bind(agent_token_hash)
    .bind(&endpoint_id)
    .bind(now)
    .bind(request.target_id.to_string())
    .bind(token_hash)
    .execute(&mut *tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::unauthorized());
    }
    tx.commit().await?;
    Ok(axum::Json(AgentEnrollmentResponse {
        target_id: request.target_id,
        agent_token,
        ticket_public_key_pem: state.inner.keys.tunnel_ticket.public_key_pem.clone(),
    }))
}

pub(crate) async fn client_control(
    State(state): State<ServerState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let user = authenticate(&state, &headers).await?;
    Ok(ws
        .max_message_size(MAX_CONTROL_MESSAGE)
        .max_frame_size(MAX_CONTROL_MESSAGE)
        .on_upgrade(move |socket| run_client_control(state, user, socket)))
}

pub(crate) async fn agent_control(
    State(state): State<ServerState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let target_id = authenticate_agent(&state, &headers).await?;
    Ok(ws
        .max_message_size(MAX_CONTROL_MESSAGE)
        .max_frame_size(MAX_CONTROL_MESSAGE)
        .on_upgrade(move |socket| run_agent_control(state, target_id, socket)))
}

pub(crate) async fn authenticate_agent(
    state: &ServerState,
    headers: &HeaderMap,
) -> Result<Uuid, ApiError> {
    let hash = hash_secret(bearer_token(headers)?);
    let row = sqlx::query(
        "SELECT id FROM targets WHERE agent_token_hash = ?1 AND enabled = 1 AND deleted_at IS NULL",
    )
    .bind(hash)
    .fetch_optional(&state.inner.db.pool)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    row_uuid(&row, "id").map_err(ApiError::from)
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
                endpoints: HashMap::new(),
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
            relay_mode,
        } => {
            if let Err(error) = open_tunnel(
                state,
                user,
                sender,
                session_id,
                target_id,
                client_endpoint_id,
                relay_mode,
            )
            .await
            {
                send_error(sender, Some(session_id), "open_denied", &error.to_string()).await;
            }
        }
        ControlMessage::Close { session_id, reason } if reason.len() <= 512 => {
            close_from_client(state, session_id, user).await;
        }
        ControlMessage::ClientReady {
            session_id,
            relay_mode,
            client_endpoint_addr,
        } => {
            if let Err(error) = send_dial_offer(
                state,
                user,
                sender,
                session_id,
                relay_mode,
                client_endpoint_addr,
            )
            .await
            {
                let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
                if let Some(runtime) = runtime
                    && runtime.client_sender.same_channel(sender)
                    && runtime.user_id == user.user_id
                    && runtime.auth_session_id == user.session_id
                    && *runtime.phase.lock().await == TunnelPhase::Pending
                {
                    fail_tunnel(state, &runtime, "client_ready_denied", &error.to_string()).await;
                    return;
                }
                send_error(
                    sender,
                    Some(session_id),
                    "client_ready_denied",
                    &error.to_string(),
                )
                .await;
            }
        }
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
        ControlMessage::AgentReady {
            session_id,
            relay_mode,
            endpoint_addr,
        } => {
            if let Err(error) = register_agent_endpoint(
                state,
                target_id,
                connection_id,
                relay_mode,
                endpoint_addr.clone(),
            )
            .await
            {
                if let Some(session_id) = session_id {
                    fail_from_target(
                        state,
                        session_id,
                        target_id,
                        connection_id,
                        "endpoint_mismatch".to_owned(),
                        error.to_string(),
                    )
                    .await;
                } else {
                    send_agent_error(
                        state,
                        target_id,
                        connection_id,
                        None,
                        "endpoint_mismatch",
                        &error.to_string(),
                    )
                    .await;
                }
            } else if let Some(session_id) = session_id {
                send_client_offer(state, target_id, connection_id, relay_mode, session_id).await;
            }
        }
        ControlMessage::IrohReady {
            session_id,
            client_endpoint_id,
            relay_mode,
        } => {
            activate_tunnel(
                state,
                target_id,
                connection_id,
                session_id,
                client_endpoint_id,
                relay_mode,
            )
            .await;
        }
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

pub(super) async fn open_tunnel(
    state: &ServerState,
    user: AuthenticatedUser,
    client_sender: &mpsc::Sender<ControlMessage>,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: String,
    relay_mode: RelayMode,
) -> Result<(), ApiError> {
    if relay_mode == RelayMode::Private
        && state
            .inner
            .transport_info
            .read()
            .await
            .private_relay_url
            .is_none()
    {
        return Err(ApiError::conflict("private Iroh relay is not configured"));
    }
    let client_endpoint_id = client_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| ApiError::bad_request("client EndpointId is invalid"))?
        .to_string();
    let target_endpoint_id = state
        .inner
        .db
        .target_endpoint_id(target_id)
        .await?
        .ok_or_else(|| ApiError::not_found("target agent is not enrolled"))?;
    let target_agent = state
        .inner
        .online_agents
        .read()
        .await
        .get(&target_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("target is offline"))?;

    let now = unix_time();
    let expires_at = (now + TICKET_TTL_SECS).min(user.access_expires_at);
    if expires_at <= now {
        return Err(ApiError::unauthorized());
    }
    let claims = TunnelTicketClaims {
        session_id,
        user_id: user.user_id,
        login_session_id: user.session_id,
        target_id,
        client_endpoint_id: client_endpoint_id.clone(),
        target_endpoint_id: target_endpoint_id.clone(),
        relay_mode,
        iss: state.inner.issuer.clone(),
        aud: TUNNEL_TICKET_AUDIENCE.to_owned(),
        iat: now as u64,
        exp: expires_at as u64,
    };
    let ticket =
        identity::encode_tunnel_ticket(&claims, &state.inner.keys.tunnel_ticket.private_key_pem)
            .map_err(ApiError::from)?;

    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    if !authorized_for_target(&mut tx, user, target_id, &target_endpoint_id, now).await? {
        return Err(ApiError::forbidden());
    }
    sqlx::query(
        "INSERT INTO tunnel_sessions(\
             id, user_id, auth_session_id, target_id, client_endpoint_id, target_endpoint_id, \
             status, created_at, expires_at\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8)",
    )
    .bind(session_id.to_string())
    .bind(user.user_id.to_string())
    .bind(user.session_id.to_string())
    .bind(target_id.to_string())
    .bind(&client_endpoint_id)
    .bind(&target_endpoint_id)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        if matches!(&error, sqlx::Error::Database(database) if database.is_unique_violation()) {
            ApiError::conflict("client EndpointId already has a pending or active SSH session")
        } else {
            ApiError::from(error)
        }
    })?;
    tx.commit().await?;

    let runtime = Arc::new(TunnelRuntime {
        session_id,
        user_id: user.user_id,
        auth_session_id: user.session_id,
        access_expires_at: user.access_expires_at,
        target_id,
        target_connection_id: target_agent.connection_id,
        relay_mode,
        client_endpoint_id: client_endpoint_id.clone(),
        target_endpoint_id,
        ticket,
        client_offer_sent: Mutex::new(false),
        client_endpoint_addr: Mutex::new(None),
        client_sender: client_sender.clone(),
        target_sender: target_agent.sender.clone(),
        phase: Mutex::new(TunnelPhase::Pending),
        expires_at,
    });
    state
        .inner
        .tunnels
        .write()
        .await
        .insert(session_id, runtime.clone());

    if runtime
        .target_sender
        .send(ControlMessage::Prepare {
            session_id,
            relay_mode,
        })
        .await
        .is_err()
    {
        close_tunnel(state, &runtime, "peer control connection closed").await;
        return Err(ApiError::conflict("peer control connection closed"));
    }
    spawn_pending_expiry(state.clone(), runtime);
    Ok(())
}

pub(super) async fn send_client_offer(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    relay_mode: RelayMode,
    session_id: Uuid,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.target_id != target_id
        || runtime.target_connection_id != connection_id
        || runtime.relay_mode != relay_mode
        || *runtime.phase.lock().await != TunnelPhase::Pending
        || runtime.expires_at <= unix_time()
    {
        return;
    }
    let mut client_offer_sent = runtime.client_offer_sent.lock().await;
    if *client_offer_sent {
        return;
    }
    let target_endpoint_id = {
        let online = state.inner.online_agents.read().await;
        let Some(agent) = online.get(&target_id).filter(|agent| {
            agent.connection_id == connection_id
                && agent.sender.same_channel(&runtime.target_sender)
        }) else {
            return;
        };
        let Some(endpoint_addr) = agent.endpoints.get(&relay_mode) else {
            return;
        };
        endpoint_addr.id.to_string()
    };
    if target_endpoint_id != runtime.target_endpoint_id {
        drop(client_offer_sent);
        fail_tunnel(
            state,
            &runtime,
            "endpoint_mismatch",
            "target EndpointId changed",
        )
        .await;
        return;
    }
    let offer = ControlMessage::ClientOffer {
        session_id,
        target_id,
        ticket: runtime.ticket.clone(),
        client_endpoint_id: runtime.client_endpoint_id.clone(),
        target_endpoint_id,
        ticket_public_key_pem: state.inner.keys.tunnel_ticket.public_key_pem.clone(),
        relay_mode,
    };
    if runtime.client_sender.send(offer).await.is_err() {
        drop(client_offer_sent);
        close_tunnel(
            state,
            &runtime,
            "client control connection closed before ClientOffer",
        )
        .await;
        return;
    }
    *client_offer_sent = true;
}

pub(super) async fn send_dial_offer(
    state: &ServerState,
    user: AuthenticatedUser,
    client_sender: &mpsc::Sender<ControlMessage>,
    session_id: Uuid,
    relay_mode: RelayMode,
    client_endpoint_addr: EndpointAddr,
) -> Result<(), ApiError> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if !runtime.client_sender.same_channel(client_sender)
        || runtime.user_id != user.user_id
        || runtime.auth_session_id != user.session_id
        || runtime.access_expires_at != user.access_expires_at
    {
        return Err(ApiError::unauthorized());
    }
    if runtime.relay_mode != relay_mode
        || *runtime.phase.lock().await != TunnelPhase::Pending
        || runtime.expires_at <= unix_time()
        || runtime.access_expires_at <= unix_time()
    {
        return Err(ApiError::conflict(
            "SSH session is not ready for client candidates",
        ));
    }
    if !*runtime.client_offer_sent.lock().await {
        return Err(ApiError::conflict(
            "target endpoint is not ready for this session",
        ));
    }
    if client_endpoint_addr.id.to_string() != runtime.client_endpoint_id
        || client_endpoint_addr.ip_addrs().count() > 32
    {
        return Err(ApiError::unauthorized());
    }
    let relay_choice = relay_choice(state, relay_mode).await?;
    crate::transport::validate_endpoint_addr(&client_endpoint_addr, &relay_choice)
        .map_err(|_| ApiError::unauthorized())?;
    if client_endpoint_addr.relay_urls().next().is_none() {
        return Err(ApiError::unauthorized());
    }

    let target_sender = {
        let online = state.inner.online_agents.read().await;
        let Some(agent) = online.get(&runtime.target_id).filter(|agent| {
            agent.connection_id == runtime.target_connection_id
                && agent.sender.same_channel(&runtime.target_sender)
        }) else {
            return Err(ApiError::conflict("target control connection changed"));
        };
        let Some(target_endpoint_addr) = agent.endpoints.get(&relay_mode) else {
            return Err(ApiError::conflict("target endpoint is not ready"));
        };
        if target_endpoint_addr.id.to_string() != runtime.target_endpoint_id {
            return Err(ApiError::unauthorized());
        }
        agent.sender.clone()
    };

    let mut registered_client_addr = runtime.client_endpoint_addr.lock().await;
    if registered_client_addr.is_some() {
        return Err(ApiError::conflict("client endpoint is already registered"));
    }
    *registered_client_addr = Some(client_endpoint_addr.clone());
    drop(registered_client_addr);

    let offer = ControlMessage::DialOffer {
        session_id,
        target_id: runtime.target_id,
        ticket: runtime.ticket.clone(),
        client_endpoint_id: runtime.client_endpoint_id.clone(),
        client_endpoint_addr,
        ticket_public_key_pem: state.inner.keys.tunnel_ticket.public_key_pem.clone(),
        relay_mode,
    };
    if target_sender.send(offer).await.is_err() {
        close_tunnel(
            state,
            &runtime,
            "target control connection closed before DialOffer",
        )
        .await;
        return Err(ApiError::conflict("target control connection closed"));
    }
    Ok(())
}

async fn authorized_for_target(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: AuthenticatedUser,
    target_id: Uuid,
    target_endpoint_id: &str,
    now: i64,
) -> Result<bool, ApiError> {
    if user.access_expires_at <= now {
        return Ok(false);
    }
    let allowed = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM users u \
         JOIN auth_sessions s ON s.user_id = u.id \
         JOIN user_roles ur ON ur.user_id = u.id \
         JOIN target_permissions tp ON tp.role_id = ur.role_id \
         JOIN targets t ON t.id = tp.target_id \
         WHERE u.id = ?1 AND u.enabled = 1 AND s.id = ?2 AND s.revoked_at IS NULL \
           AND s.refresh_expires_at > ?3 AND t.id = ?4 AND t.enabled = 1 \
           AND t.deleted_at IS NULL AND t.agent_endpoint_id = ?5 \
           AND tp.permission = 'ssh_connect')",
    )
    .bind(user.user_id.to_string())
    .bind(user.session_id.to_string())
    .bind(now)
    .bind(target_id.to_string())
    .bind(target_endpoint_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(allowed != 0)
}

pub(super) async fn register_agent_endpoint(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    relay_mode: RelayMode,
    endpoint_addr: EndpointAddr,
) -> Result<(), ApiError> {
    let endpoint_id = state
        .inner
        .db
        .target_endpoint_id(target_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if endpoint_addr.id.to_string() != endpoint_id || endpoint_addr.ip_addrs().count() > 32 {
        return Err(ApiError::unauthorized());
    }
    let relay_choice = relay_choice(state, relay_mode).await?;
    crate::transport::validate_endpoint_addr(&endpoint_addr, &relay_choice)
        .map_err(|_| ApiError::unauthorized())?;
    if endpoint_addr.relay_urls().next().is_none() {
        return Err(ApiError::unauthorized());
    }
    let mut online = state.inner.online_agents.write().await;
    let agent = online
        .get_mut(&target_id)
        .filter(|agent| agent.connection_id == connection_id)
        .ok_or_else(ApiError::unauthorized)?;
    agent.endpoints.insert(relay_mode, endpoint_addr);
    Ok(())
}

async fn relay_choice(
    state: &ServerState,
    relay_mode: RelayMode,
) -> Result<crate::transport::RelayChoice, ApiError> {
    let transport = state.inner.transport_info.read().await.clone();
    match relay_mode {
        RelayMode::Private => {
            let relay_url = transport
                .private_relay_url
                .ok_or_else(ApiError::unauthorized)?;
            Ok(crate::transport::RelayChoice::Private {
                url: reqwest::Url::parse(&relay_url).map_err(|_| ApiError::unauthorized())?,
                qad_port: transport.qad_port,
            })
        }
        RelayMode::PublicDefault => Ok(crate::transport::RelayChoice::PublicDefault),
    }
}

pub(super) async fn activate_tunnel(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    client_endpoint_id: String,
    relay_mode: RelayMode,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.target_id != target_id
        || runtime.target_connection_id != connection_id
        || runtime.client_endpoint_id != client_endpoint_id
        || runtime.relay_mode != relay_mode
    {
        return;
    }
    let mut phase = runtime.phase.lock().await;
    if *phase != TunnelPhase::Pending
        || !*runtime.client_offer_sent.lock().await
        || runtime.client_endpoint_addr.lock().await.is_none()
    {
        return;
    }
    let now = unix_time();
    let activation = async {
        let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
        if runtime.expires_at <= now
            || runtime.access_expires_at <= now
            || !authorized_for_target(
                &mut tx,
                AuthenticatedUser {
                    user_id: runtime.user_id,
                    session_id: runtime.auth_session_id,
                    access_expires_at: runtime.access_expires_at,
                },
                target_id,
                &runtime.target_endpoint_id,
                now,
            )
            .await?
        {
            sqlx::query(
                "UPDATE tunnel_sessions SET status = 'closed', closed_at = ?1 \
                 WHERE id = ?2 AND status = 'pending'",
            )
            .bind(now)
            .bind(session_id.to_string())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok::<bool, ApiError>(false);
        }
        let updated = sqlx::query(
            "UPDATE tunnel_sessions SET status = 'active', activated_at = ?1 \
             WHERE id = ?2 AND status = 'pending' AND expires_at > ?1 \
               AND client_endpoint_id = ?3 AND target_endpoint_id = ?4",
        )
        .bind(now)
        .bind(session_id.to_string())
        .bind(&runtime.client_endpoint_id)
        .bind(&runtime.target_endpoint_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(updated.rows_affected() == 1)
    }
    .await;

    match activation {
        Ok(true) => {
            *phase = TunnelPhase::Active;
            drop(phase);
            let activated = ControlMessage::Activated { session_id };
            let _ = runtime.client_sender.send(activated.clone()).await;
            let _ = runtime.target_sender.send(activated).await;
        }
        Ok(false) => {
            *phase = TunnelPhase::Closed;
            drop(phase);
            let error = ControlMessage::Error {
                session_id: Some(session_id),
                code: "authorization".to_owned(),
                message: "SSH authorization expired or changed before activation".to_owned(),
            };
            let _ = runtime.client_sender.send(error.clone()).await;
            let _ = runtime.target_sender.send(error).await;
            remove_tunnel(state, session_id, &runtime).await;
        }
        Err(error) => {
            drop(phase);
            tracing::error!(session = %session_id, error = %error, "activate Iroh SSH session failed");
            fail_tunnel(
                state,
                &runtime,
                "activation_failed",
                "server could not activate SSH session",
            )
            .await;
        }
    }
}

async fn close_from_client(state: &ServerState, session_id: Uuid, user: AuthenticatedUser) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.user_id == user.user_id && runtime.auth_session_id == user.session_id {
        close_tunnel(state, &runtime, "client closed SSH session").await;
    }
}

async fn close_from_target(
    state: &ServerState,
    session_id: Uuid,
    target_id: Uuid,
    connection_id: Uuid,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    let active = *runtime.phase.lock().await == TunnelPhase::Active;
    if runtime.target_id == target_id && (runtime.target_connection_id == connection_id || active) {
        close_tunnel(state, &runtime, "target closed SSH session").await;
    }
}

async fn fail_from_target(
    state: &ServerState,
    session_id: Uuid,
    target_id: Uuid,
    connection_id: Uuid,
    code: String,
    message: String,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    let active = *runtime.phase.lock().await == TunnelPhase::Active;
    if runtime.target_id == target_id && (runtime.target_connection_id == connection_id || active) {
        fail_tunnel(state, &runtime, &code, &message).await;
    }
}

pub(super) async fn close_pending_client_tunnels(
    state: &ServerState,
    client_sender: &mpsc::Sender<ControlMessage>,
) {
    let runtimes = state
        .inner
        .tunnels
        .read()
        .await
        .values()
        .filter(|runtime| runtime.client_sender.same_channel(client_sender))
        .cloned()
        .collect::<Vec<_>>();
    for runtime in runtimes {
        close_pending_tunnel(state, &runtime, "client control connection closed").await;
    }
}

async fn close_pending_target_tunnels(state: &ServerState, target_id: Uuid, connection_id: Uuid) {
    let runtimes = state
        .inner
        .tunnels
        .read()
        .await
        .values()
        .filter(|runtime| {
            runtime.target_id == target_id && runtime.target_connection_id == connection_id
        })
        .cloned()
        .collect::<Vec<_>>();
    for runtime in runtimes {
        close_pending_tunnel(state, &runtime, "target control connection closed").await;
    }
}

async fn unregister_agent(state: &ServerState, target_id: Uuid, connection_id: Uuid) {
    let mut online = state.inner.online_agents.write().await;
    if online
        .get(&target_id)
        .is_some_and(|agent| agent.connection_id == connection_id)
    {
        online.remove(&target_id);
    }
    drop(online);
    close_pending_target_tunnels(state, target_id, connection_id).await;
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

fn spawn_pending_expiry(state: ServerState, runtime: Arc<TunnelRuntime>) {
    tokio::spawn(async move {
        let seconds = runtime.expires_at.saturating_sub(unix_time()).max(0) as u64;
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        close_pending_tunnel(
            &state,
            &runtime,
            "SSH authorization expired before activation",
        )
        .await;
    });
}

async fn close_tunnel(state: &ServerState, runtime: &Arc<TunnelRuntime>, reason: &str) {
    let mut phase = runtime.phase.lock().await;
    if *phase == TunnelPhase::Closed {
        return;
    }
    *phase = TunnelPhase::Closed;
    drop(phase);
    finish_tunnel_close(state, runtime, reason).await;
}

async fn close_pending_tunnel(state: &ServerState, runtime: &Arc<TunnelRuntime>, reason: &str) {
    let mut phase = runtime.phase.lock().await;
    if *phase != TunnelPhase::Pending {
        return;
    }
    *phase = TunnelPhase::Closed;
    drop(phase);
    finish_tunnel_close(state, runtime, reason).await;
}

async fn finish_tunnel_close(state: &ServerState, runtime: &Arc<TunnelRuntime>, reason: &str) {
    let _ = sqlx::query(
        "UPDATE tunnel_sessions SET status = 'closed', closed_at = ?1 \
         WHERE id = ?2 AND status IN ('pending', 'active')",
    )
    .bind(unix_time())
    .bind(runtime.session_id.to_string())
    .execute(&state.inner.db.pool)
    .await;
    let message = ControlMessage::Close {
        session_id: runtime.session_id,
        reason: reason.to_owned(),
    };
    let _ = runtime.client_sender.send(message.clone()).await;
    let _ = runtime.target_sender.send(message).await;
    remove_tunnel(state, runtime.session_id, runtime).await;
}

async fn fail_tunnel(state: &ServerState, runtime: &Arc<TunnelRuntime>, code: &str, message: &str) {
    let mut phase = runtime.phase.lock().await;
    if *phase == TunnelPhase::Closed {
        return;
    }
    *phase = TunnelPhase::Closed;
    drop(phase);
    let _ = sqlx::query(
        "UPDATE tunnel_sessions SET status = 'closed', closed_at = ?1 \
         WHERE id = ?2 AND status IN ('pending', 'active')",
    )
    .bind(unix_time())
    .bind(runtime.session_id.to_string())
    .execute(&state.inner.db.pool)
    .await;
    let error = ControlMessage::Error {
        session_id: Some(runtime.session_id),
        code: code.to_owned(),
        message: message.to_owned(),
    };
    let _ = runtime.client_sender.send(error.clone()).await;
    let _ = runtime.target_sender.send(error).await;
    remove_tunnel(state, runtime.session_id, runtime).await;
}

async fn remove_tunnel(state: &ServerState, session_id: Uuid, runtime: &Arc<TunnelRuntime>) {
    let mut tunnels = state.inner.tunnels.write().await;
    if tunnels
        .get(&session_id)
        .is_some_and(|current| Arc::ptr_eq(current, runtime))
    {
        tunnels.remove(&session_id);
    }
}
