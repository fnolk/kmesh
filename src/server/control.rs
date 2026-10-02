use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::extract::{
    State,
    ws::{Message, WebSocket, WebSocketUpgrade},
};
use axum::http::HeaderMap;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use futures_util::{SinkExt, StreamExt};
use sqlx::Row;
use tokio::sync::{Mutex, mpsc, watch};
use uuid::Uuid;

use crate::identity::{self, TUNNEL_TICKET_AUDIENCE};
use crate::protocol::{
    AgentEnrollmentRequest, AgentEnrollmentResponse, ControlMessage, LocalCandidate,
    NatObservation, NatPlan, PeerRole, SelectedPath, StunMapping, TunnelTicketClaims,
};

use super::auth::{AuthenticatedUser, authenticate, bearer_token};
use super::db::{row_uuid, unix_time};
use super::error::ApiError;
use super::{ServerState, hash_secret, new_secret};

const DIRECT_TICKET_TTL_SECS: i64 = 60;
const PENDING_TUNNEL_TTL_SECS: u64 = 65;
const MAX_NAT_LOCAL_CANDIDATES: usize = 128;
const MAX_NAT_STUN_MAPPINGS: usize = 16;
const MAX_NAT_PLAN_CANDIDATES: usize = 8;

#[derive(Clone)]
pub struct OnlineAgent {
    pub(crate) connection_id: Uuid,
    pub(crate) sender: mpsc::Sender<ControlMessage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelPhase {
    Pending,
    RelaySelected,
    Active(SelectedPath),
    Closed,
}

pub(crate) struct TunnelState {
    pub phase: TunnelPhase,
    pub client_quic_ready: bool,
    pub target_quic_ready: bool,
    client_nat_observation: Option<NatObservation>,
    target_nat_observation: Option<NatObservation>,
    nat_plan_sent: bool,
}

pub(crate) struct TunnelRuntime {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub auth_session_id: Uuid,
    pub target_id: Uuid,
    pub target_connection_id: Uuid,
    pub client_sender: mpsc::Sender<ControlMessage>,
    pub target_sender: mpsc::Sender<ControlMessage>,
    pub state: Mutex<TunnelState>,
    pub phase_tx: watch::Sender<TunnelPhase>,
    pub relay_slots: Mutex<super::relay::RelaySlots>,
    pub expires_at: i64,
}

pub(crate) async fn enroll(
    State(state): State<ServerState>,
    axum::Json(request): axum::Json<AgentEnrollmentRequest>,
) -> Result<axum::Json<AgentEnrollmentResponse>, ApiError> {
    if request.enrollment_token.len() > 256 || request.certificate_der.len() > 64 * 1024 {
        return Err(ApiError::bad_request("enrollment request is too large"));
    }
    if request.certificate_der.is_empty() {
        return Err(ApiError::bad_request("agent certificate is empty"));
    }
    validate_certificate_der(&request.certificate_der)?;
    let token_hash = hash_secret(&request.enrollment_token);
    let now = unix_time();
    let agent_token = new_secret();
    let agent_token_hash = hash_secret(&agent_token);
    let fingerprint = certificate_fingerprint(&request.certificate_der);
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
             agent_token_hash = ?1, agent_certificate_der = ?2, agent_certificate_fingerprint = ?3, \
             enrolled_at = ?4, updated_at = ?4 WHERE id = ?5 AND enrollment_token_hash = ?6 \
             AND enrollment_expires_at > ?4 AND enabled = 1",
    )
    .bind(agent_token_hash)
    .bind(&request.certificate_der)
    .bind(fingerprint)
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
        .max_message_size(256 * 1024)
        .max_frame_size(256 * 1024)
        .on_upgrade(move |socket| run_client_control(state, user, socket)))
}

pub(crate) async fn agent_control(
    State(state): State<ServerState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let target_id = authenticate_agent(&state, &headers).await?;
    Ok(ws
        .max_message_size(256 * 1024)
        .max_frame_size(256 * 1024)
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
    let (sender, receiver) = mpsc::channel(128);
    let (mut sink, mut stream) = socket.split();
    let last_pong = Arc::new(AtomicI64::new(unix_time()));
    let writer_last_pong = last_pong.clone();
    let mut writer = tokio::spawn(async move {
        let mut receiver = receiver;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(20));
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
                    Err(_) => send_error(&sender, None, "invalid_message", "invalid control message".to_owned()).await,
                },
                Some(Ok(Message::Pong(_))) => { last_pong.store(unix_time(), Ordering::Relaxed); }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Binary(_))) => {}
            },
            _ = &mut writer => break,
        }
    }
    writer.abort();
    close_pending_user_tunnels(&state, user.user_id, user.session_id, &sender).await;
}

async fn run_agent_control(state: ServerState, target_id: Uuid, socket: WebSocket) {
    let connection_id = Uuid::new_v4();
    let (sender, mut receiver) = mpsc::channel(128);
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
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(20));
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

async fn handle_client_message(
    state: &ServerState,
    user: AuthenticatedUser,
    client_sender: &mpsc::Sender<ControlMessage>,
    message: ControlMessage,
) {
    match message {
        ControlMessage::Open {
            session_id,
            target_id,
            client_public_key,
        } => {
            if let Err(error) = open_tunnel(
                state,
                user,
                client_sender,
                session_id,
                target_id,
                client_public_key,
            )
            .await
            {
                send_error(
                    client_sender,
                    Some(session_id),
                    "open_denied",
                    error.to_string(),
                )
                .await;
            }
        }
        ControlMessage::Candidates {
            session_id,
            observation,
        } => {
            if !valid_nat_observation(&observation) {
                send_error(
                    client_sender,
                    Some(session_id),
                    "invalid_candidates",
                    "NAT observation is invalid".to_owned(),
                )
                .await;
                return;
            }
            if let Err(error) = submit_nat_observation(
                state,
                session_id,
                Endpoint::Client(user),
                Some(client_sender),
                observation,
            )
            .await
            {
                send_error(
                    client_sender,
                    Some(session_id),
                    "invalid_candidates",
                    error.to_owned(),
                )
                .await;
            }
        }
        ControlMessage::ProbeSeen {
            session_id,
            peer: PeerRole::Client,
            candidate,
        } if valid_candidate(candidate) => {
            route_client_message(
                state,
                user,
                session_id,
                ControlMessage::ProbeSeen {
                    session_id,
                    peer: PeerRole::Client,
                    candidate,
                },
            )
            .await;
        }
        ControlMessage::QuicReady { session_id } => {
            route_quic_ready(
                state,
                session_id,
                Endpoint::Client(user),
                ControlMessage::QuicReady { session_id },
            )
            .await;
        }
        ControlMessage::SelectRelay { session_id } => {
            select_relay(state, session_id, Endpoint::Client(user)).await;
        }
        ControlMessage::Cancel { session_id, reason } => {
            cancel_tunnel(state, session_id, Endpoint::Client(user), reason).await;
        }
        _ => {
            send_error(
                client_sender,
                None,
                "invalid_direction",
                "message is not valid from a client".to_owned(),
            )
            .await
        }
    }
}

async fn handle_agent_message(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    message: ControlMessage,
) {
    match message {
        ControlMessage::Candidates {
            session_id,
            observation,
        } => {
            if !valid_nat_observation(&observation) {
                send_agent_error(
                    state,
                    target_id,
                    connection_id,
                    Some(session_id),
                    "invalid_candidates",
                    "NAT observation is invalid",
                )
                .await;
                return;
            }
            if let Err(error) = submit_nat_observation(
                state,
                session_id,
                Endpoint::Target {
                    target_id,
                    connection_id,
                },
                None,
                observation,
            )
            .await
            {
                send_agent_error(
                    state,
                    target_id,
                    connection_id,
                    Some(session_id),
                    "invalid_candidates",
                    error,
                )
                .await;
            }
        }
        ControlMessage::ProbeSeen {
            session_id,
            peer: PeerRole::Target,
            candidate,
        } if valid_candidate(candidate) => {
            route_agent_message(
                state,
                target_id,
                connection_id,
                session_id,
                ControlMessage::ProbeSeen {
                    session_id,
                    peer: PeerRole::Target,
                    candidate,
                },
            )
            .await;
        }
        ControlMessage::QuicReady { session_id } => {
            route_quic_ready(
                state,
                session_id,
                Endpoint::Target {
                    target_id,
                    connection_id,
                },
                ControlMessage::QuicReady { session_id },
            )
            .await;
        }
        ControlMessage::SelectRelay { session_id } => {
            select_relay(
                state,
                session_id,
                Endpoint::Target {
                    target_id,
                    connection_id,
                },
            )
            .await;
        }
        ControlMessage::Activate { session_id, path } => {
            activate_path(state, target_id, connection_id, session_id, path).await;
        }
        ControlMessage::Cancel { session_id, reason } => {
            cancel_tunnel(
                state,
                session_id,
                Endpoint::Target {
                    target_id,
                    connection_id,
                },
                reason,
            )
            .await;
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

#[derive(Clone, Copy)]
pub(super) enum Endpoint {
    Client(AuthenticatedUser),
    Target {
        target_id: Uuid,
        connection_id: Uuid,
    },
}

pub(super) async fn open_tunnel(
    state: &ServerState,
    user: AuthenticatedUser,
    client_sender: &mpsc::Sender<ControlMessage>,
    session_id: Uuid,
    target_id: Uuid,
    client_public_key: String,
) -> Result<(), ApiError> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(client_public_key.as_bytes())
        .map_err(|_| ApiError::bad_request("client ephemeral key is invalid"))?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("client ephemeral key is invalid"))?;
    VerifyingKey::from_bytes(&key_array)
        .map_err(|_| ApiError::bad_request("client ephemeral key is invalid"))?;

    let target_agent = state
        .inner
        .online_agents
        .read()
        .await
        .get(&target_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("target is offline"))?;
    let (target_certificate_der, target_certificate_fingerprint) = state
        .inner
        .db
        .target_certificate(target_id)
        .await?
        .ok_or_else(|| ApiError::not_found("target agent is not enrolled"))?;
    let now = unix_time();
    let expires_at = now + DIRECT_TICKET_TTL_SECS;
    let probe_token = new_secret();
    let ticket_claims = TunnelTicketClaims {
        session_id,
        user_id: user.user_id,
        login_session_id: user.session_id,
        target_id,
        client_public_key: client_public_key.clone(),
        target_certificate_fingerprint,
        iss: state.inner.issuer.clone(),
        aud: TUNNEL_TICKET_AUDIENCE.to_owned(),
        iat: now as u64,
        exp: expires_at as u64,
    };
    let ticket = identity::encode_tunnel_ticket(
        &ticket_claims,
        &state.inner.keys.tunnel_ticket.private_key_pem,
    )
    .map_err(ApiError::from)?;
    let mut sessions = state.inner.tunnels.write().await;
    if sessions.contains_key(&session_id) {
        return Err(ApiError::conflict("tunnel session already exists"));
    }
    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    if !authorized_for_target(&mut tx, user, target_id).await? {
        return Err(ApiError::forbidden());
    }
    sqlx::query(
        "INSERT INTO tunnel_sessions(id, user_id, auth_session_id, target_id, client_public_key, status, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
    )
    .bind(session_id.to_string())
    .bind(user.user_id.to_string())
    .bind(user.session_id.to_string())
    .bind(target_id.to_string())
    .bind(&client_public_key)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let runtime = Arc::new(TunnelRuntime::new(
        session_id,
        user,
        target_id,
        target_agent.connection_id,
        client_sender.clone(),
        target_agent.sender.clone(),
        expires_at,
    ));
    sessions.insert(session_id, runtime.clone());
    drop(sessions);

    let offer = ControlMessage::Offer {
        session_id,
        target_id,
        ticket,
        client_public_key,
        probe_token,
        target_certificate_der,
        ticket_public_key_pem: state.inner.keys.tunnel_ticket.public_key_pem.clone(),
    };
    if runtime.target_sender.send(offer.clone()).await.is_err()
        || runtime.client_sender.send(offer).await.is_err()
    {
        close_tunnel(state, &runtime, "peer control connection closed").await;
        return Err(ApiError::conflict("peer control connection closed"));
    }
    spawn_pending_expiry(state.clone(), runtime);
    Ok(())
}

async fn authorized_for_target(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: AuthenticatedUser,
    target_id: Uuid,
) -> Result<bool, ApiError> {
    let allowed = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM users u \
         JOIN auth_sessions s ON s.user_id = u.id \
         JOIN user_roles ur ON ur.user_id = u.id \
         JOIN target_permissions tp ON tp.role_id = ur.role_id \
         JOIN targets t ON t.id = tp.target_id \
         WHERE u.id = ?1 AND u.enabled = 1 AND s.id = ?2 AND s.revoked_at IS NULL \
           AND s.refresh_expires_at >= ?3 AND t.id = ?4 AND t.enabled = 1 AND t.deleted_at IS NULL \
           AND tp.permission = 'ssh_connect')",
    )
    .bind(user.user_id.to_string())
    .bind(user.session_id.to_string())
    .bind(unix_time())
    .bind(target_id.to_string())
    .fetch_one(&mut **tx)
    .await?;
    Ok(allowed != 0)
}

pub(super) async fn submit_nat_observation(
    state: &ServerState,
    session_id: Uuid,
    endpoint: Endpoint,
    client_sender: Option<&mpsc::Sender<ControlMessage>>,
    observation: NatObservation,
) -> Result<(), &'static str> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return Ok(());
    };
    let endpoint_matches = match endpoint {
        Endpoint::Client(user) => {
            runtime.user_id == user.user_id
                && runtime.auth_session_id == user.session_id
                && client_sender.is_some_and(|sender| runtime.client_sender.same_channel(sender))
        }
        Endpoint::Target {
            target_id,
            connection_id,
        } => runtime.target_id == target_id && runtime.target_connection_id == connection_id,
    };
    if !endpoint_matches {
        return Ok(());
    }

    let plan = {
        let mut tunnel_state = runtime.state.lock().await;
        if tunnel_state.phase != TunnelPhase::Pending {
            return Ok(());
        }
        let observation_slot = match endpoint {
            Endpoint::Client(_) => &mut tunnel_state.client_nat_observation,
            Endpoint::Target { .. } => &mut tunnel_state.target_nat_observation,
        };
        if observation_slot.is_some() {
            return Err("NAT observation was already submitted");
        }
        *observation_slot = Some(observation);
        let plan = if tunnel_state.nat_plan_sent {
            None
        } else {
            tunnel_state
                .client_nat_observation
                .as_ref()
                .zip(tunnel_state.target_nat_observation.as_ref())
                .map(|(client, target)| build_nat_plan(client, target))
        };
        if plan.is_some() {
            tunnel_state.nat_plan_sent = true;
        }
        plan
    };

    if let Some(plan) = plan {
        let message = ControlMessage::NatPlan { session_id, plan };
        if runtime.client_sender.send(message.clone()).await.is_err()
            || runtime.target_sender.send(message).await.is_err()
        {
            close_tunnel(
                state,
                &runtime,
                "control connection closed while sending NAT plan",
            )
            .await;
        }
    }
    Ok(())
}

pub(super) fn valid_nat_observation(observation: &NatObservation) -> bool {
    observation.local_candidates.len() <= MAX_NAT_LOCAL_CANDIDATES
        && observation.stun_mappings.len() <= MAX_NAT_STUN_MAPPINGS
        && (!observation.local_candidates.is_empty() || !observation.stun_mappings.is_empty())
        && observation.local_candidates.iter().all(|candidate| {
            valid_candidate(candidate.address)
                && match candidate.address.ip() {
                    std::net::IpAddr::V4(_) => candidate.prefix_len <= 32,
                    std::net::IpAddr::V6(_) => candidate.prefix_len <= 128,
                }
        })
        && observation.stun_mappings.iter().all(|mapping| {
            valid_candidate(mapping.server)
                && mapping
                    .mapped
                    .is_none_or(|candidate| valid_candidate(candidate))
        })
}

pub(super) fn build_nat_plan(client: &NatObservation, target: &NatObservation) -> NatPlan {
    NatPlan {
        client_remote_candidates: remote_candidates(client, target),
        target_remote_candidates: remote_candidates(target, client),
    }
}

fn remote_candidates(local: &NatObservation, remote: &NatObservation) -> Vec<std::net::SocketAddr> {
    let mut candidates = Vec::with_capacity(MAX_NAT_PLAN_CANDIDATES);
    for mapping in &remote.stun_mappings {
        if let Some(mapped) = mapping.mapped {
            push_candidate(&mut candidates, mapped);
        }
    }

    for peer in &remote.local_candidates {
        if usable_lan_candidate(peer.address)
            && local
                .local_candidates
                .iter()
                .any(|local| usable_lan_candidate(local.address) && prefixes_overlap(local, peer))
        {
            push_candidate(&mut candidates, peer.address);
        }
    }

    if candidates.len() < MAX_NAT_PLAN_CANDIDATES {
        let remaining = MAX_NAT_PLAN_CANDIDATES - candidates.len();
        for candidate in bounded_port_samples(&remote.stun_mappings, remaining) {
            push_candidate(&mut candidates, candidate);
            if candidates.len() == MAX_NAT_PLAN_CANDIDATES {
                break;
            }
        }
    }
    candidates
}

fn push_candidate(candidates: &mut Vec<std::net::SocketAddr>, candidate: std::net::SocketAddr) {
    if candidates.len() < MAX_NAT_PLAN_CANDIDATES && !candidates.contains(&candidate) {
        candidates.push(candidate);
    }
}

fn bounded_port_samples(mappings: &[StunMapping], limit: usize) -> Vec<std::net::SocketAddr> {
    if mappings.len() != 3
        || mappings[0].server == mappings[1].server
        || mappings[0].server != mappings[2].server
    {
        return Vec::new();
    }
    let (Some(first), Some(middle), Some(last)) =
        (mappings[0].mapped, mappings[1].mapped, mappings[2].mapped)
    else {
        return Vec::new();
    };
    if first != last || first.ip() != middle.ip() {
        return Vec::new();
    }

    let low = u32::from(first.port().min(middle.port()));
    let high = u32::from(first.port().max(middle.port()));
    let span = high - low;
    if span <= 1 {
        return Vec::new();
    }
    let sample_count = ((span - 1) as usize).min(limit);
    let denominator = (sample_count + 1) as u32;
    (1..=sample_count)
        .map(|index| {
            let index = index as u32;
            let offset = (span * index + denominator / 2) / denominator;
            std::net::SocketAddr::new(first.ip(), (low + offset) as u16)
        })
        .collect()
}

fn usable_lan_candidate(address: std::net::SocketAddr) -> bool {
    if !valid_candidate(address) || address.ip().is_loopback() {
        return false;
    }
    match address.ip() {
        std::net::IpAddr::V4(ip) => !ip.octets().starts_with(&[169, 254]),
        std::net::IpAddr::V6(ip) => ip.segments()[0] & 0xffc0 != 0xfe80,
    }
}

fn prefixes_overlap(left: &LocalCandidate, right: &LocalCandidate) -> bool {
    let prefix_len = left.prefix_len.min(right.prefix_len);
    if prefix_len == 0 {
        return false;
    }
    match (left.address.ip(), right.address.ip()) {
        (std::net::IpAddr::V4(left), std::net::IpAddr::V4(right)) => {
            let mask = u32::MAX << (32 - prefix_len);
            u32::from(left) & mask == u32::from(right) & mask
        }
        (std::net::IpAddr::V6(left), std::net::IpAddr::V6(right)) => {
            let mask = u128::MAX << (128 - u32::from(prefix_len));
            u128::from(left) & mask == u128::from(right) & mask
        }
        _ => false,
    }
}

async fn route_client_message(
    state: &ServerState,
    user: AuthenticatedUser,
    session_id: Uuid,
    message: ControlMessage,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.user_id != user.user_id || runtime.auth_session_id != user.session_id {
        return;
    }
    if runtime.target_sender.send(message).await.is_err() {
        close_tunnel(state, &runtime, "target control connection closed").await;
    }
}

async fn route_agent_message(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    message: ControlMessage,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
        return;
    }
    if runtime.client_sender.send(message).await.is_err() {
        close_tunnel(state, &runtime, "client control connection closed").await;
    }
}

async fn route_quic_ready(
    state: &ServerState,
    session_id: Uuid,
    endpoint: Endpoint,
    message: ControlMessage,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    let mut tunnel_state = runtime.state.lock().await;
    if tunnel_state.phase != TunnelPhase::Pending {
        return;
    }
    let other = match endpoint {
        Endpoint::Client(user)
            if runtime.user_id == user.user_id && runtime.auth_session_id == user.session_id =>
        {
            tunnel_state.client_quic_ready = true;
            runtime.target_sender.clone()
        }
        Endpoint::Target {
            target_id,
            connection_id,
        } if runtime.target_id == target_id && runtime.target_connection_id == connection_id => {
            tunnel_state.target_quic_ready = true;
            runtime.client_sender.clone()
        }
        _ => return,
    };
    drop(tunnel_state);
    let _ = other.send(message).await;
}

pub(super) async fn select_relay(state: &ServerState, session_id: Uuid, endpoint: Endpoint) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    let valid_endpoint = match endpoint {
        Endpoint::Client(user) => {
            runtime.user_id == user.user_id && runtime.auth_session_id == user.session_id
        }
        Endpoint::Target {
            target_id,
            connection_id,
        } => runtime.target_id == target_id && runtime.target_connection_id == connection_id,
    };
    if !valid_endpoint {
        return;
    }
    let mut tunnel_state = runtime.state.lock().await;
    if tunnel_state.phase != TunnelPhase::Pending {
        return;
    }
    tunnel_state.phase = TunnelPhase::RelaySelected;
    runtime.phase_tx.send_replace(TunnelPhase::RelaySelected);
    drop(tunnel_state);
    let message = ControlMessage::SelectRelay { session_id };
    let _ = runtime.client_sender.send(message.clone()).await;
    let _ = runtime.target_sender.send(message).await;
}

pub(super) async fn activate_path(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    path: SelectedPath,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
        return;
    }
    let mut tunnel_state = runtime.state.lock().await;
    let selected = match (tunnel_state.phase, path) {
        (TunnelPhase::RelaySelected, SelectedPath::Relay) => true,
        (TunnelPhase::Pending, SelectedPath::Quic) => {
            tunnel_state.client_quic_ready && tunnel_state.target_quic_ready
        }
        _ => false,
    };
    if !selected || unix_time() >= runtime.expires_at {
        drop(tunnel_state);
        send_error(
            &runtime.target_sender,
            Some(session_id),
            "path_not_ready",
            "path cannot be activated".to_owned(),
        )
        .await;
        return;
    }

    let now = unix_time();
    let activation = async {
        let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
        if !authorized_for_target(
            &mut tx,
            AuthenticatedUser {
                user_id: runtime.user_id,
                session_id: runtime.auth_session_id,
            },
            target_id,
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
        let path_text = match path {
            SelectedPath::Quic => "quic",
            SelectedPath::Relay => "relay",
        };
        let updated = sqlx::query(
            "UPDATE tunnel_sessions SET status = 'active', selected_path = ?1, activated_at = ?2 \
             WHERE id = ?3 AND status = 'pending'",
        )
        .bind(path_text)
        .bind(now)
        .bind(session_id.to_string())
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::conflict("tunnel path was already activated"));
        }
        tx.commit().await?;
        Ok(true)
    }
    .await;

    match activation {
        Ok(true) => {
            tunnel_state.phase = TunnelPhase::Active(path);
            runtime.phase_tx.send_replace(TunnelPhase::Active(path));
            drop(tunnel_state);
            let activated = ControlMessage::Activated { session_id, path };
            let _ = runtime.client_sender.send(activated.clone()).await;
            let _ = runtime.target_sender.send(activated).await;
            if path == SelectedPath::Quic {
                let mut tunnels = state.inner.tunnels.write().await;
                if tunnels
                    .get(&session_id)
                    .is_some_and(|current| Arc::ptr_eq(current, &runtime))
                {
                    tunnels.remove(&session_id);
                }
            }
        }
        Ok(false) => {
            drop(tunnel_state);
            close_tunnel(state, &runtime, "access revoked before activation").await;
        }
        Err(error) => {
            drop(tunnel_state);
            send_error(
                &runtime.target_sender,
                Some(session_id),
                "activation_failed",
                error.to_string(),
            )
            .await;
        }
    }
}

pub(super) async fn cancel_tunnel(
    state: &ServerState,
    session_id: Uuid,
    endpoint: Endpoint,
    reason: String,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        let _ = close_direct_audit_session(state, session_id, endpoint).await;
        return;
    };
    let authorized = match endpoint {
        Endpoint::Client(user) => {
            runtime.user_id == user.user_id && runtime.auth_session_id == user.session_id
        }
        Endpoint::Target {
            target_id,
            connection_id,
        } => runtime.target_id == target_id && runtime.target_connection_id == connection_id,
    };
    if authorized {
        close_tunnel(state, &runtime, &reason).await;
    }
}

async fn close_direct_audit_session(
    state: &ServerState,
    session_id: Uuid,
    endpoint: Endpoint,
) -> Result<(), ApiError> {
    match endpoint {
        Endpoint::Client(user) => {
            sqlx::query(
                "UPDATE tunnel_sessions SET status = 'closed', closed_at = ?1 \
                 WHERE id = ?2 AND user_id = ?3 AND auth_session_id = ?4 \
                   AND status = 'active' AND selected_path = 'quic'",
            )
            .bind(unix_time())
            .bind(session_id.to_string())
            .bind(user.user_id.to_string())
            .bind(user.session_id.to_string())
            .execute(&state.inner.db.pool)
            .await?;
        }
        Endpoint::Target { target_id, .. } => {
            sqlx::query(
                "UPDATE tunnel_sessions SET status = 'closed', closed_at = ?1 \
                 WHERE id = ?2 AND target_id = ?3 AND status = 'active' AND selected_path = 'quic'",
            )
            .bind(unix_time())
            .bind(session_id.to_string())
            .bind(target_id.to_string())
            .execute(&state.inner.db.pool)
            .await?;
        }
    }
    Ok(())
}

pub(crate) async fn close_tunnel(state: &ServerState, runtime: &Arc<TunnelRuntime>, reason: &str) {
    {
        let mut tunnel_state = runtime.state.lock().await;
        if tunnel_state.phase == TunnelPhase::Closed {
            return;
        }
        tunnel_state.phase = TunnelPhase::Closed;
        runtime.phase_tx.send_replace(TunnelPhase::Closed);
    }
    let now = unix_time();
    let _ = sqlx::query(
        "UPDATE tunnel_sessions SET status = 'closed', closed_at = ?1 \
         WHERE id = ?2 AND status != 'closed'",
    )
    .bind(now)
    .bind(runtime.session_id.to_string())
    .execute(&state.inner.db.pool)
    .await;
    let cancel = ControlMessage::Cancel {
        session_id: runtime.session_id,
        reason: reason.to_owned(),
    };
    let _ = runtime.client_sender.send(cancel.clone()).await;
    let _ = runtime.target_sender.send(cancel).await;
    state
        .inner
        .tunnels
        .write()
        .await
        .remove(&runtime.session_id);
}

pub(super) async fn close_pending_user_tunnels(
    state: &ServerState,
    user_id: Uuid,
    auth_session_id: Uuid,
    sender: &mpsc::Sender<ControlMessage>,
) {
    let sessions = state
        .inner
        .tunnels
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for runtime in sessions {
        if runtime.user_id != user_id
            || runtime.auth_session_id != auth_session_id
            || !runtime.client_sender.same_channel(sender)
        {
            continue;
        }
        let phase = runtime.state.lock().await.phase;
        if matches!(phase, TunnelPhase::Pending | TunnelPhase::RelaySelected) {
            close_tunnel(state, &runtime, "client control disconnected").await;
        }
    }
}

async fn unregister_agent(state: &ServerState, target_id: Uuid, connection_id: Uuid) {
    {
        let mut online = state.inner.online_agents.write().await;
        if online
            .get(&target_id)
            .is_some_and(|agent| agent.connection_id == connection_id)
        {
            online.remove(&target_id);
        }
    }
    let sessions = state
        .inner
        .tunnels
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for runtime in sessions {
        if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
            continue;
        }
        let phase = runtime.state.lock().await.phase;
        if matches!(phase, TunnelPhase::Pending | TunnelPhase::RelaySelected) {
            close_tunnel(state, &runtime, "target control disconnected").await;
        }
    }
}

fn spawn_pending_expiry(state: ServerState, runtime: Arc<TunnelRuntime>) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(PENDING_TUNNEL_TTL_SECS)).await;
        let phase = runtime.state.lock().await.phase;
        if matches!(phase, TunnelPhase::Pending | TunnelPhase::RelaySelected) {
            close_tunnel(&state, &runtime, "tunnel establishment expired").await;
        }
    });
}

async fn send_error(
    sender: &mpsc::Sender<ControlMessage>,
    session_id: Option<Uuid>,
    code: &str,
    message: String,
) {
    let _ = sender
        .send(ControlMessage::Error {
            session_id,
            code: code.to_owned(),
            message,
        })
        .await;
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
        send_error(&sender, session_id, code, message.to_owned()).await;
    }
}

fn valid_candidate(candidate: std::net::SocketAddr) -> bool {
    if candidate.port() == 0 || candidate.ip().is_unspecified() || candidate.ip().is_multicast() {
        return false;
    }
    match candidate.ip() {
        std::net::IpAddr::V4(ip) => !ip.is_broadcast(),
        std::net::IpAddr::V6(_) => true,
    }
}

fn validate_certificate_der(der: &[u8]) -> Result<(), ApiError> {
    let certificate = rustls::pki_types::CertificateDer::from(der.to_vec());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate)
        .map_err(|_| ApiError::bad_request("invalid target certificate DER"))
}

fn certificate_fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(der)))
}

impl TunnelRuntime {
    fn new(
        session_id: Uuid,
        user: AuthenticatedUser,
        target_id: Uuid,
        target_connection_id: Uuid,
        client_sender: mpsc::Sender<ControlMessage>,
        target_sender: mpsc::Sender<ControlMessage>,
        expires_at: i64,
    ) -> Self {
        let (phase_tx, _) = watch::channel(TunnelPhase::Pending);
        Self {
            session_id,
            user_id: user.user_id,
            auth_session_id: user.session_id,
            target_id,
            target_connection_id,
            client_sender,
            target_sender,
            state: Mutex::new(TunnelState {
                phase: TunnelPhase::Pending,
                client_quic_ready: false,
                target_quic_ready: false,
                client_nat_observation: None,
                target_nat_observation: None,
                nat_plan_sent: false,
            }),
            phase_tx,
            relay_slots: Mutex::new(super::relay::RelaySlots::default()),
            expires_at,
        }
    }
}
