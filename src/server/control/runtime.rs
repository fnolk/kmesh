use std::{sync::Arc, time::Duration};

use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::protocol::{ControlMessage, RouteMode, SelectedPath};

use super::{
    ServerState,
    auth::AuthenticatedUser,
    db::unix_time,
    error::ApiError,
    punch::{PunchSelection, PunchStage},
    send_agent_error, send_error,
    tunnel::authorized_for_target,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelPhase {
    Pending,
    Active,
    Closed,
}

pub(super) struct PendingTransport {
    pub(super) target_data_endpoint_id: Option<String>,
    pub(super) ticket: Option<String>,
    pub(super) client_offer_sent: bool,
    pub(super) target_endpoint_addr: Option<EndpointAddr>,
    pub(super) client_endpoint_addr: Option<EndpointAddr>,
    pub(super) target_discovery: Option<ReadyDiscovery>,
    pub(super) client_discovery: Option<ReadyDiscovery>,
    pub(super) punch_stage: PunchStage,
    pub(super) target_punch_ready: bool,
    pub(super) client_punch_ready: bool,
    pub(super) target_selection: Option<PunchSelection>,
    pub(super) client_selection: Option<PunchSelection>,
    pub(super) target_path: Option<SelectedPath>,
    pub(super) client_path: Option<SelectedPath>,
    pub(super) target_iroh_ready: bool,
    pub(super) dial_offer_sent: bool,
}

impl Default for PendingTransport {
    fn default() -> Self {
        Self {
            target_data_endpoint_id: None,
            ticket: None,
            client_offer_sent: false,
            target_endpoint_addr: None,
            client_endpoint_addr: None,
            target_discovery: None,
            client_discovery: None,
            punch_stage: PunchStage::WaitingCandidates,
            target_punch_ready: false,
            client_punch_ready: false,
            target_selection: None,
            client_selection: None,
            target_path: None,
            client_path: None,
            target_iroh_ready: false,
            dial_offer_sent: false,
        }
    }
}

pub(crate) struct TunnelRuntime {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub auth_session_id: Uuid,
    pub access_expires_at: i64,
    pub target_id: Uuid,
    pub target_connection_id: Uuid,
    pub route_mode: RouteMode,
    pub client_endpoint_id: String,
    /// Stable registered device identity, retained for enrollment and live authorization.
    pub target_endpoint_id: String,
    pub(super) setup: Mutex<PendingTransport>,
    pub client_sender: mpsc::Sender<ControlMessage>,
    pub target_sender: mpsc::Sender<ControlMessage>,
    pub phase: Mutex<TunnelPhase>,
    pub expires_at: i64,
}

pub(super) async fn fail_from_client(
    state: &ServerState,
    user: AuthenticatedUser,
    sender: &mpsc::Sender<ControlMessage>,
    session_id: Uuid,
    code: &str,
    message: &str,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    if let Some(runtime) = runtime
        && runtime.client_sender.same_channel(sender)
        && runtime.user_id == user.user_id
        && runtime.auth_session_id == user.session_id
        && *runtime.phase.lock().await == TunnelPhase::Pending
    {
        fail_tunnel(state, &runtime, code, message).await;
    } else {
        send_error(sender, Some(session_id), code, message).await;
    }
}

pub(super) async fn allow_agent_data_endpoint(
    state: &ServerState,
    endpoint_id: &str,
) -> Result<bool, ApiError> {
    let runtimes = state
        .inner
        .tunnels
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for runtime in runtimes {
        let data_endpoint_matches = runtime
            .setup
            .lock()
            .await
            .target_data_endpoint_id
            .as_deref()
            == Some(endpoint_id);
        if !data_endpoint_matches || *runtime.phase.lock().await == TunnelPhase::Closed {
            continue;
        }
        return state
            .inner
            .db
            .tunnel_session_can_use_relay(runtime.session_id)
            .await
            .map_err(ApiError::from);
    }
    Ok(false)
}

pub(super) async fn activate_tunnel(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    client_endpoint_id: String,
    target_data_endpoint_id: String,
    route_mode: RouteMode,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.target_id != target_id
        || runtime.target_connection_id != connection_id
        || runtime.client_endpoint_id != client_endpoint_id
        || runtime.route_mode != route_mode
    {
        return;
    }
    let mut phase = runtime.phase.lock().await;
    if *phase != TunnelPhase::Pending {
        return;
    }
    let setup = runtime.setup.lock().await;
    let route_paths_ready = match runtime.route_mode {
        RouteMode::PrivateDirect | RouteMode::PublicDirect => matches!(
            (&setup.client_path, &setup.target_path),
            (
                Some(SelectedPath::Direct { .. }),
                Some(SelectedPath::Direct { .. })
            )
        ),
        RouteMode::PrivateRelay => matches!(
            (&setup.client_path, &setup.target_path),
            (
                Some(SelectedPath::PrivateRelay { .. }),
                Some(SelectedPath::PrivateRelay { .. })
            )
        ),
    };
    if setup.punch_stage != PunchStage::NativePlanned
        || !setup.client_offer_sent
        || !setup.dial_offer_sent
        || !setup.target_iroh_ready
        || !route_paths_ready
        || setup.target_data_endpoint_id.as_deref() != Some(target_data_endpoint_id.as_str())
        || setup.target_endpoint_addr.is_none()
        || setup.client_endpoint_addr.is_none()
        || setup.ticket.is_none()
    {
        return;
    }
    drop(setup);
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

pub(super) async fn close_from_client(
    state: &ServerState,
    session_id: Uuid,
    user: AuthenticatedUser,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        return;
    };
    if runtime.user_id == user.user_id && runtime.auth_session_id == user.session_id {
        close_tunnel(state, &runtime, "client closed SSH session").await;
    }
}

pub(super) async fn close_from_target(
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

pub(super) async fn fail_from_target(
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

pub(super) async fn fail_pending_from_target(
    state: &ServerState,
    session_id: Uuid,
    target_id: Uuid,
    connection_id: Uuid,
    code: String,
    message: String,
) {
    let runtime = state.inner.tunnels.read().await.get(&session_id).cloned();
    let Some(runtime) = runtime else {
        send_agent_error(
            state,
            target_id,
            connection_id,
            Some(session_id),
            &code,
            &message,
        )
        .await;
        return;
    };
    if runtime.target_id == target_id
        && runtime.target_connection_id == connection_id
        && *runtime.phase.lock().await == TunnelPhase::Pending
    {
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

pub(super) async fn unregister_agent(state: &ServerState, target_id: Uuid, connection_id: Uuid) {
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
