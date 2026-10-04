use std::sync::Arc;

use iroh::EndpointAddr;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::{
    identity::{self, TUNNEL_TICKET_AUDIENCE},
    protocol::{ControlMessage, RouteMode, SelectedPath, TunnelTicketClaims},
};

use super::super::{auth::AuthenticatedUser, db::unix_time, error::ApiError};
use super::{
    ServerState,
    punch::PunchStage,
    runtime::{PendingTransport, TunnelPhase, TunnelRuntime, close_tunnel, spawn_pending_expiry},
};

const TICKET_TTL_SECS: i64 = 60;

pub(in crate::server) async fn open_tunnel(
    state: &ServerState,
    user: AuthenticatedUser,
    client_sender: &mpsc::Sender<ControlMessage>,
    session_id: Uuid,
    target_id: Uuid,
    client_endpoint_id: String,
    route_mode: RouteMode,
) -> Result<(), ApiError> {
    if route_mode == RouteMode::PrivateRelay
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
    let mut tunnels = state.inner.tunnels.write().await;
    if tunnels.contains_key(&session_id) {
        return Err(ApiError::conflict("SSH session ID is already in use"));
    }
    for existing in tunnels.values() {
        if *existing.phase.lock().await == TunnelPhase::Closed {
            continue;
        }
        if existing.client_endpoint_id == client_endpoint_id
            || existing
                .setup
                .lock()
                .await
                .target_data_endpoint_id
                .as_deref()
                == Some(client_endpoint_id.as_str())
        {
            return Err(ApiError::conflict(
                "client EndpointId is already bound to a pending or active SSH session",
            ));
        }
    }
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
        route_mode,
        client_endpoint_id: client_endpoint_id.clone(),
        target_endpoint_id,
        setup: Mutex::new(PendingTransport::default()),
        client_sender: client_sender.clone(),
        target_sender: target_agent.sender.clone(),
        phase: Mutex::new(TunnelPhase::Pending),
        expires_at,
    });
    tunnels.insert(session_id, runtime.clone());
    drop(tunnels);

    if runtime
        .target_sender
        .send(ControlMessage::Prepare {
            session_id,
            route_mode,
            client_endpoint_id,
            expires_at,
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

pub(super) async fn register_agent_identity(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    route_mode: RouteMode,
    target_data_endpoint_id: String,
    signature: Vec<u8>,
) -> Result<(), ApiError> {
    let registered_device_id = state
        .inner
        .db
        .target_endpoint_id(target_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let data_endpoint_id = target_data_endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| ApiError::bad_request("target data EndpointId is invalid"))?;
    let canonical_data_endpoint_id = data_endpoint_id.to_string();

    let tunnels = state.inner.tunnels.write().await;
    let runtime = tunnels
        .get(&session_id)
        .cloned()
        .ok_or_else(ApiError::unauthorized)?;
    if runtime.target_id != target_id
        || runtime.target_connection_id != connection_id
        || runtime.route_mode != route_mode
        || runtime.target_endpoint_id != registered_device_id
        || registered_device_id == canonical_data_endpoint_id
        || runtime.client_endpoint_id == canonical_data_endpoint_id
        || runtime.expires_at <= unix_time()
    {
        return Err(ApiError::unauthorized());
    }
    identity::verify_agent_session_identity(
        &registered_device_id,
        session_id,
        target_id,
        route_mode,
        &canonical_data_endpoint_id,
        runtime.expires_at,
        &signature,
    )
    .map_err(|_| ApiError::unauthorized())?;

    let phase = runtime.phase.lock().await;
    if *phase != TunnelPhase::Pending || runtime.expires_at <= unix_time() {
        return Err(ApiError::conflict("SSH session is no longer pending"));
    }
    for (other_session_id, other) in tunnels.iter() {
        if *other_session_id == session_id {
            continue;
        }
        if *other.phase.lock().await == TunnelPhase::Closed {
            continue;
        }
        let other_target_id = other.setup.lock().await.target_data_endpoint_id.clone();
        if other.client_endpoint_id == canonical_data_endpoint_id
            || other_target_id.as_deref() == Some(canonical_data_endpoint_id.as_str())
        {
            return Err(ApiError::conflict(
                "target data EndpointId is already bound to another session",
            ));
        }
    }
    let mut setup = runtime.setup.lock().await;
    if setup.target_data_endpoint_id.is_some() || setup.ticket.is_some() {
        return Err(ApiError::conflict(
            "target data EndpointId is already bound for this session",
        ));
    }
    let now = unix_time();
    if runtime.expires_at <= now || runtime.access_expires_at <= now {
        return Err(ApiError::unauthorized());
    }
    let claims = TunnelTicketClaims {
        session_id,
        user_id: runtime.user_id,
        login_session_id: runtime.auth_session_id,
        target_id,
        client_endpoint_id: runtime.client_endpoint_id.clone(),
        target_endpoint_id: canonical_data_endpoint_id.clone(),
        route_mode,
        iss: state.inner.issuer.clone(),
        aud: TUNNEL_TICKET_AUDIENCE.to_owned(),
        iat: now as u64,
        exp: runtime.expires_at as u64,
    };
    let ticket =
        identity::encode_tunnel_ticket(&claims, &state.inner.keys.tunnel_ticket.private_key_pem)
            .map_err(ApiError::from)?;
    setup.target_data_endpoint_id = Some(canonical_data_endpoint_id);
    setup.ticket = Some(ticket);
    if route_mode == RouteMode::PrivateRelay {
        setup.punch_stage = PunchStage::NativePlanned;
    }
    drop(setup);
    drop(phase);
    drop(tunnels);
    Ok(())
}

pub(super) async fn send_client_offer(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    route_mode: RouteMode,
    session_id: Uuid,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.target_id != target_id
        || runtime.target_connection_id != connection_id
        || runtime.route_mode != route_mode
        || *runtime.phase.lock().await != TunnelPhase::Pending
        || runtime.expires_at <= unix_time()
    {
        return;
    }
    let online = state.inner.online_agents.read().await;
    if !online.get(&target_id).is_some_and(|agent| {
        agent.connection_id == connection_id && agent.sender.same_channel(&runtime.target_sender)
    }) {
        return;
    }
    drop(online);

    let offer = {
        let mut setup = runtime.setup.lock().await;
        if setup.client_offer_sent {
            return;
        }
        let (Some(target_endpoint_id), Some(ticket)) =
            (setup.target_data_endpoint_id.clone(), setup.ticket.clone())
        else {
            return;
        };
        setup.client_offer_sent = true;
        ControlMessage::ClientOffer {
            session_id,
            target_id,
            ticket,
            client_endpoint_id: runtime.client_endpoint_id.clone(),
            target_endpoint_id,
            ticket_public_key_pem: state.inner.keys.tunnel_ticket.public_key_pem.clone(),
            route_mode,
        }
    };
    if runtime.client_sender.send(offer).await.is_err() {
        close_tunnel(
            state,
            &runtime,
            "client control connection closed before ClientOffer",
        )
        .await;
    }
}

pub(super) async fn register_client_endpoint(
    state: &ServerState,
    user: AuthenticatedUser,
    client_sender: &mpsc::Sender<ControlMessage>,
    session_id: Uuid,
    route_mode: RouteMode,
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
    if runtime.route_mode != route_mode
        || *runtime.phase.lock().await != TunnelPhase::Pending
        || runtime.expires_at <= unix_time()
        || runtime.access_expires_at <= unix_time()
    {
        return Err(ApiError::conflict("SSH session is not pending"));
    }
    let mut setup = runtime.setup.lock().await;
    if !setup.client_offer_sent || setup.punch_stage != PunchStage::NativePlanned {
        return Err(ApiError::conflict("native transport is not ready"));
    }
    if client_endpoint_addr.id.to_string() != runtime.client_endpoint_id
        || client_endpoint_addr.ip_addrs().count() > 32
        || setup.client_endpoint_addr.is_some()
    {
        return Err(ApiError::unauthorized());
    }
    validate_route_endpoint_addr(state, route_mode, &client_endpoint_addr).await?;
    setup.client_endpoint_addr = Some(client_endpoint_addr);
    Ok(())
}

pub(super) async fn register_agent_data_endpoint(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    route_mode: RouteMode,
    endpoint_addr: EndpointAddr,
) -> Result<(), ApiError> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if runtime.target_id != target_id
        || runtime.target_connection_id != connection_id
        || runtime.route_mode != route_mode
        || *runtime.phase.lock().await != TunnelPhase::Pending
        || runtime.expires_at <= unix_time()
    {
        return Err(ApiError::unauthorized());
    }
    let online = state.inner.online_agents.read().await;
    if !online
        .get(&target_id)
        .is_some_and(|agent| agent.connection_id == connection_id)
    {
        return Err(ApiError::unauthorized());
    }
    drop(online);
    let mut setup = runtime.setup.lock().await;
    let endpoint_id = endpoint_addr.id.to_string();
    if setup.punch_stage != PunchStage::NativePlanned
        || setup.target_endpoint_addr.is_some()
        || setup.target_data_endpoint_id.as_deref() != Some(endpoint_id.as_str())
        || endpoint_addr.ip_addrs().count() > 32
    {
        return Err(ApiError::unauthorized());
    }
    validate_route_endpoint_addr(state, route_mode, &endpoint_addr).await?;
    setup.target_endpoint_addr = Some(endpoint_addr);
    Ok(())
}

pub(super) async fn maybe_send_dial_offer(
    state: &ServerState,
    runtime: &Arc<TunnelRuntime>,
) -> Result<(), ApiError> {
    let offer = {
        let mut setup = runtime.setup.lock().await;
        if setup.dial_offer_sent
            || setup.punch_stage != PunchStage::NativePlanned
            || !setup.client_offer_sent
        {
            return Ok(());
        }
        let (Some(target_endpoint_addr), Some(client_endpoint_addr), Some(ticket)) = (
            setup.target_endpoint_addr.clone(),
            setup.client_endpoint_addr.clone(),
            setup.ticket.clone(),
        ) else {
            return Ok(());
        };
        let Some(target_endpoint_id) = setup.target_data_endpoint_id.clone() else {
            return Err(ApiError::unauthorized());
        };
        if target_endpoint_addr.id.to_string() != target_endpoint_id {
            return Err(ApiError::unauthorized());
        }
        setup.dial_offer_sent = true;
        ControlMessage::DialOffer {
            session_id: runtime.session_id,
            target_id: runtime.target_id,
            ticket,
            client_endpoint_id: runtime.client_endpoint_id.clone(),
            client_endpoint_addr,
            ticket_public_key_pem: state.inner.keys.tunnel_ticket.public_key_pem.clone(),
            route_mode: runtime.route_mode,
        }
    };
    let online = state.inner.online_agents.read().await;
    let Some(agent) = online.get(&runtime.target_id).filter(|agent| {
        agent.connection_id == runtime.target_connection_id
            && agent.sender.same_channel(&runtime.target_sender)
    }) else {
        return Err(ApiError::conflict("target control connection changed"));
    };
    let sender = agent.sender.clone();
    drop(online);
    if sender.send(offer).await.is_err() {
        close_tunnel(
            state,
            runtime,
            "target control connection closed before DialOffer",
        )
        .await;
        return Err(ApiError::conflict("target control connection closed"));
    }
    Ok(())
}

pub(super) async fn register_path_ready(
    state: &ServerState,
    session_id: Uuid,
    route_mode: RouteMode,
    path: SelectedPath,
    client: Option<(AuthenticatedUser, &mpsc::Sender<ControlMessage>)>,
    target: Option<(Uuid, Uuid)>,
) -> Result<Arc<TunnelRuntime>, ApiError> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if runtime.route_mode != route_mode
        || *runtime.phase.lock().await != TunnelPhase::Pending
        || runtime.expires_at <= unix_time()
    {
        return Err(ApiError::conflict("SSH route attempt is not pending"));
    }
    let client_side = client.is_some();
    match (client, target) {
        (Some((user, sender)), None) => {
            if !runtime.client_sender.same_channel(sender)
                || runtime.user_id != user.user_id
                || runtime.auth_session_id != user.session_id
                || runtime.access_expires_at != user.access_expires_at
            {
                return Err(ApiError::unauthorized());
            }
        }
        (None, Some((target_id, connection_id))) => {
            if runtime.target_id != target_id || runtime.target_connection_id != connection_id {
                return Err(ApiError::unauthorized());
            }
            let online = state.inner.online_agents.read().await;
            if !online.get(&target_id).is_some_and(|agent| {
                agent.connection_id == connection_id
                    && agent.sender.same_channel(&runtime.target_sender)
            }) {
                return Err(ApiError::unauthorized());
            }
        }
        _ => return Err(ApiError::unauthorized()),
    }
    validate_selected_path(state, route_mode, &path).await?;

    let mut setup = runtime.setup.lock().await;
    if !setup.dial_offer_sent
        || setup.target_endpoint_addr.is_none()
        || setup.client_endpoint_addr.is_none()
    {
        return Err(ApiError::conflict("Iroh peer connection is not ready"));
    }
    let slot = if client_side {
        &mut setup.client_path
    } else {
        &mut setup.target_path
    };
    if slot.is_some() {
        return Err(ApiError::conflict("selected path was already reported"));
    }
    *slot = Some(path);
    drop(setup);
    Ok(runtime)
}

async fn validate_selected_path(
    state: &ServerState,
    route_mode: RouteMode,
    path: &SelectedPath,
) -> Result<(), ApiError> {
    match (route_mode, path) {
        (
            RouteMode::PrivateDirect | RouteMode::PublicDirect,
            SelectedPath::Direct { remote_address },
        ) if !remote_address.ip().is_unspecified() && remote_address.port() != 0 => Ok(()),
        (RouteMode::PrivateRelay, SelectedPath::PrivateRelay { url }) => {
            let transport = state.inner.transport_info.read().await;
            let private_url = transport
                .private_relay_url
                .as_deref()
                .ok_or_else(|| ApiError::conflict("private relay is not configured"))?;
            let reported = reqwest::Url::parse(url)
                .map_err(|_| ApiError::bad_request("selected private relay URL is invalid"))?;
            let expected =
                reqwest::Url::parse(private_url).map_err(|_| ApiError::unauthorized())?;
            if reported.as_str() != expected.as_str() {
                return Err(ApiError::unauthorized());
            }
            Ok(())
        }
        (RouteMode::PrivateDirect | RouteMode::PublicDirect, _) => Err(ApiError::conflict(
            "direct route requires a selected IP path",
        )),
        (RouteMode::PrivateRelay, _) => Err(ApiError::conflict(
            "private relay route requires the configured private relay path",
        )),
    }
}

pub(super) async fn register_agent_iroh_ready(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    client_endpoint_id: String,
    target_data_endpoint_id: String,
    route_mode: RouteMode,
) -> Result<Arc<TunnelRuntime>, ApiError> {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let runtime = runtime.ok_or_else(ApiError::unauthorized)?;
    if runtime.target_id != target_id
        || runtime.target_connection_id != connection_id
        || runtime.client_endpoint_id != client_endpoint_id
        || runtime.route_mode != route_mode
        || *runtime.phase.lock().await != TunnelPhase::Pending
    {
        return Err(ApiError::unauthorized());
    }
    let online = state.inner.online_agents.read().await;
    if !online.get(&target_id).is_some_and(|agent| {
        agent.connection_id == connection_id && agent.sender.same_channel(&runtime.target_sender)
    }) {
        return Err(ApiError::unauthorized());
    }
    drop(online);
    let mut setup = runtime.setup.lock().await;
    if !setup.dial_offer_sent
        || setup.target_data_endpoint_id.as_deref() != Some(target_data_endpoint_id.as_str())
        || setup.target_endpoint_addr.is_none()
        || setup.client_endpoint_addr.is_none()
        || setup.target_iroh_ready
    {
        return Err(ApiError::unauthorized());
    }
    setup.target_iroh_ready = true;
    drop(setup);
    Ok(runtime)
}

pub(super) async fn maybe_activate_tunnel(state: &ServerState, runtime: &Arc<TunnelRuntime>) {
    let target_data_endpoint_id = {
        let setup = runtime.setup.lock().await;
        if !setup.target_iroh_ready || setup.client_path.is_none() || setup.target_path.is_none() {
            return;
        }
        let Some(target_data_endpoint_id) = setup.target_data_endpoint_id.clone() else {
            return;
        };
        target_data_endpoint_id
    };
    super::runtime::activate_tunnel(
        state,
        runtime.target_id,
        runtime.target_connection_id,
        runtime.session_id,
        runtime.client_endpoint_id.clone(),
        target_data_endpoint_id,
        runtime.route_mode,
    )
    .await;
}

pub(super) async fn authorized_for_target(
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

pub(super) async fn validate_route_endpoint_addr(
    state: &ServerState,
    route_mode: RouteMode,
    endpoint_addr: &EndpointAddr,
) -> Result<(), ApiError> {
    let ip_addrs = endpoint_addr.ip_addrs().collect::<Vec<_>>();
    if ip_addrs.len() > 32
        || ip_addrs
            .iter()
            .any(|address| address.ip().is_unspecified() || address.port() == 0)
    {
        return Err(ApiError::unauthorized());
    }
    match route_mode {
        RouteMode::PrivateDirect | RouteMode::PublicDirect => {
            if ip_addrs.is_empty() || endpoint_addr.relay_urls().next().is_some() {
                return Err(ApiError::unauthorized());
            }
        }
        RouteMode::PrivateRelay => {
            if !ip_addrs.is_empty() || endpoint_addr.relay_urls().count() != 1 {
                return Err(ApiError::unauthorized());
            }
            let relay_choice = private_relay_choice(state).await?;
            crate::transport::validate_endpoint_addr(endpoint_addr, &relay_choice)
                .map_err(|_| ApiError::unauthorized())?;
        }
    }
    Ok(())
}

async fn private_relay_choice(
    state: &ServerState,
) -> Result<crate::transport::RelayChoice, ApiError> {
    let transport = state.inner.transport_info.read().await.clone();
    let relay_url = transport
        .private_relay_url
        .ok_or_else(|| ApiError::conflict("private relay is not configured"))?;
    Ok(crate::transport::RelayChoice::Private {
        url: reqwest::Url::parse(&relay_url).map_err(|_| ApiError::unauthorized())?,
        quic_port: transport.qad_port,
    })
}
