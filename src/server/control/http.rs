use axum::{
    extract::{State, ws::WebSocketUpgrade},
    http::HeaderMap,
    response::Response,
};
use sqlx::Row;

use super::super::{
    ServerState,
    auth::{authenticate, bearer_token},
    db::unix_time,
    error::ApiError,
};
use super::MAX_CONTROL_MESSAGE;
use crate::protocol::{AgentEnrollmentRequest, AgentEnrollmentResponse};

pub(in crate::server) async fn transport_info(
    State(state): State<ServerState>,
) -> axum::Json<crate::protocol::TransportInfo> {
    axum::Json(state.inner.transport_info.read().await.clone())
}

pub(in crate::server) async fn enroll(
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
    let target_id = super::super::admin::normalize_target_id(&request.target_id)?;
    let token_hash = super::super::hash_secret(&request.enrollment_token);
    let now = unix_time();
    let agent_token = super::super::new_secret();
    let agent_token_hash = super::super::hash_secret(&agent_token);
    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let target = sqlx::query(
        "SELECT enrollment_token_hash, enrollment_expires_at, enabled, deleted_at FROM targets WHERE id = ?1",
    )
    .bind(&target_id)
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
    .bind(&target_id)
    .bind(token_hash)
    .execute(&mut *tx)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::unauthorized());
    }
    tx.commit().await?;
    Ok(axum::Json(AgentEnrollmentResponse {
        target_id,
        agent_token,
        ticket_public_key_pem: state.inner.keys.tunnel_ticket.public_key_pem.clone(),
    }))
}

pub(in crate::server) async fn client_control(
    State(state): State<ServerState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let user = authenticate(&state, &headers).await?;
    if let Some(message) = client_version_mismatch(&headers) {
        return Ok(ws.on_upgrade(move |socket| super::reject_incompatible_version(socket, message)));
    }
    Ok(ws
        .max_message_size(MAX_CONTROL_MESSAGE)
        .max_frame_size(MAX_CONTROL_MESSAGE)
        .on_upgrade(move |socket| super::run_client_control(state, user, socket)))
}

pub(in crate::server) async fn agent_control(
    State(state): State<ServerState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let target_id = authenticate_agent(&state, &headers).await?;
    if let Some(message) = client_version_mismatch(&headers) {
        return Ok(ws.on_upgrade(move |socket| super::reject_incompatible_version(socket, message)));
    }
    Ok(ws
        .max_message_size(MAX_CONTROL_MESSAGE)
        .max_frame_size(MAX_CONTROL_MESSAGE)
        .on_upgrade(move |socket| super::run_agent_control(state, target_id, socket)))
}

fn client_version_mismatch(headers: &HeaderMap) -> Option<String> {
    let version = headers
        .get(crate::version::VERSION_HEADER)
        .and_then(|value| value.to_str().ok());
    crate::version::mismatch(version)
}

pub(in crate::server) async fn authenticate_agent(
    state: &ServerState,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let hash = super::super::hash_secret(bearer_token(headers)?);
    let row = sqlx::query(
        "SELECT id FROM targets WHERE agent_token_hash = ?1 AND enabled = 1 AND deleted_at IS NULL",
    )
    .bind(hash)
    .fetch_optional(&state.inner.db.pool)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    row.try_get("id").map_err(ApiError::from)
}
