use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant, UNIX_EPOCH},
};

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use sqlx::Row;
use uuid::Uuid;

use crate::protocol::{
    AdminOperation, AdminRequest, AdminResponse, ApiTokenView, MeView, RelayConnectionMetadata,
    RelayConnectionView, RelayEndpointSide, RelaySessionPhase, RelayTrafficView, RoleGrantView,
    RoleView, TargetPermission, TargetView, UserKeyView, UserView,
};

use super::auth::{authenticate, canonical_ssh_key, ssh_fingerprint};
use super::db::{row_uuid, unix_time};
use super::error::ApiError;
use super::{ServerState, control, hash_secret, new_secret};

pub(crate) async fn me(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<MeView>, ApiError> {
    let user = authenticate(&state, &headers).await?;
    let user_view = get_user(&state, &user.user_id).await?;
    let roles = list_user_roles(&state, &user.user_id).await?;
    Ok(Json(MeView {
        user: user_view,
        roles,
    }))
}

pub(crate) async fn targets(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TargetView>>, ApiError> {
    let user = authenticate(&state, &headers).await?;
    let rows = sqlx::query(
        "SELECT DISTINCT t.id, t.name FROM targets t \
         JOIN target_permissions tp ON tp.target_id = t.id \
         JOIN user_roles ur ON ur.role_id = tp.role_id \
         WHERE ur.user_id = ?1 AND tp.permission = 'ssh_connect' \
           AND t.enabled = 1 AND t.deleted_at IS NULL ORDER BY t.name COLLATE NOCASE",
    )
    .bind(&user.user_id)
    .fetch_all(&state.inner.db.pool)
    .await?;
    let online = state.inner.online_agents.read().await;
    let views = rows
        .into_iter()
        .map(|row| {
            let id: String = row.try_get("id")?;
            Ok(TargetView {
                target_id: id.clone(),
                name: row.try_get("name")?,
                enabled: true,
                online: online.contains_key(&id),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(views))
}

pub(crate) async fn operation(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<AdminRequest>,
) -> Result<Json<AdminResponse>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    if !state.inner.db.is_admin(&actor.user_id).await? {
        return Err(ApiError::forbidden());
    }
    Ok(Json(
        apply_operation(&state, actor.user_id, request.operation).await?,
    ))
}

pub(crate) async fn apply_operation(
    state: &ServerState,
    actor_user_id: String,
    operation: AdminOperation,
) -> Result<AdminResponse, ApiError> {
    use AdminOperation as Op;

    let mut operation = operation;
    match &mut operation {
        Op::SetUserEnabled { user_id, .. }
        | Op::CreateApiToken { user_id, .. }
        | Op::ListApiTokens { user_id }
        | Op::AddUserKey { user_id, .. }
        | Op::ListKeys { user_id }
        | Op::ListUserRoles { user_id } => *user_id = normalize_username(user_id)?,
        Op::SetUserRoles { user_id, role_ids } => {
            *user_id = normalize_username(user_id)?;
            for role_id in role_ids {
                *role_id = normalize_role_id(role_id)?;
            }
        }
        Op::DeleteRole { role_id } | Op::ListRoleGrants { role_id } => {
            *role_id = normalize_role_id(role_id)?;
        }
        Op::GrantTarget {
            role_id, target_id, ..
        }
        | Op::RevokeTarget {
            role_id, target_id, ..
        } => {
            *role_id = normalize_role_id(role_id)?;
            *target_id = normalize_target_id(target_id)?;
        }
        Op::RenameTarget { target_id, .. }
        | Op::SetTargetEnabled { target_id, .. }
        | Op::DeleteTarget { target_id }
        | Op::IssueEnrollment { target_id } => {
            *target_id = normalize_target_id(target_id)?;
        }
        _ => {}
    }

    match &operation {
        Op::ListUsers => return Ok(AdminResponse::Users(list_users(state).await?)),
        Op::ListRelayTraffic => {
            return Ok(AdminResponse::RelayTraffic(
                list_relay_traffic(state).await?,
            ));
        }
        Op::CloseRelaySession { session_id } => {
            return close_relay_session(state, actor_user_id, *session_id).await;
        }
        Op::ListApiTokens { user_id } => {
            return Ok(AdminResponse::ApiTokens(
                list_api_tokens(state, user_id).await?,
            ));
        }
        Op::ListKeys { user_id } => {
            return Ok(AdminResponse::Keys(list_keys(state, user_id).await?));
        }
        Op::ListRoles => return Ok(AdminResponse::Roles(list_roles(state).await?)),
        Op::ListUserRoles { user_id } => {
            return Ok(AdminResponse::UserRoles(
                list_user_roles(state, user_id).await?,
            ));
        }
        Op::ListRoleGrants { role_id } => {
            return Ok(AdminResponse::Grants(
                list_role_grants(state, role_id).await?,
            ));
        }
        Op::ListTargets => return Ok(AdminResponse::Targets(list_targets(state).await?)),
        _ => {}
    }

    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let mut audit = prepare_audit_event(actor_user_id, &operation, &mut tx).await?;
    let response = apply_operation_write(state, &mut tx, operation).await?;
    complete_audit_event(&mut audit, &response);
    insert_audit_event(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(response)
}

async fn insert_audit_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    audit: AuditEvent,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO admin_audit(id, occurred_at, actor_user_id, operation, object_type, object_id, context_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(audit.id.to_string())
    .bind(audit.occurred_at)
    .bind(audit.actor_user_id)
    .bind(audit.operation)
    .bind(audit.object_type)
    .bind(audit.object_id)
    .bind(serde_json::to_string(&audit.context).map_err(ApiError::internal)?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn list_relay_traffic(state: &ServerState) -> Result<RelayTrafficView, ApiError> {
    let clients = state.inner.relay_clients.read().await.clone();
    let Some(clients) = clients else {
        return Ok(RelayTrafficView {
            enabled: false,
            sample_duration_ms: 0,
            bytes_received: 0,
            bytes_sent: 0,
            bytes_received_per_second: 0.0,
            bytes_sent_per_second: 0.0,
            relay_connection_count: 0,
            ssh_session_count: 0,
            connections: Vec::new(),
        });
    };

    let sample_started = Instant::now();
    let before = clients.traffic_snapshot();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after = clients.traffic_snapshot();
    let sample_duration = sample_started.elapsed();

    let label_rows = sqlx::query(
        "SELECT ts.id, u.username, t.name AS target_name FROM tunnel_sessions ts \
         JOIN users u ON u.id = ts.user_id JOIN targets t ON t.id = ts.target_id \
         WHERE ts.status IN ('pending', 'active')",
    )
    .fetch_all(&state.inner.db.pool)
    .await?;
    let labels = label_rows
        .into_iter()
        .map(|row| {
            Ok((
                row_uuid(&row, "id")?,
                (
                    row.try_get::<String, _>("username")?,
                    row.try_get::<String, _>("target_name")?,
                ),
            ))
        })
        .collect::<Result<HashMap<_, _>, ApiError>>()?;
    let before_by_connection = before
        .connections
        .iter()
        .map(|connection| {
            (
                (
                    connection.endpoint_id.to_string(),
                    connection.connection_id.as_u64(),
                ),
                (connection.bytes_received, connection.bytes_sent),
            )
        })
        .collect::<HashMap<_, _>>();

    let runtimes = state
        .inner
        .tunnels
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut metadata_by_endpoint = HashMap::new();
    for runtime in runtimes {
        if runtime.route_mode != crate::protocol::RouteMode::PrivateRelay {
            continue;
        }
        let phase = *runtime.phase.lock().await;
        let (client_endpoint_id, target_data_endpoint_id) =
            control::relay_endpoint_ids(&runtime).await;
        let (username, target_name) = labels
            .get(&runtime.session_id)
            .map(|(username, target_name)| (username.clone(), target_name.clone()))
            .unwrap_or_else(|| (runtime.user_id.clone(), runtime.target_id.clone()));
        let session_phase = match phase {
            control::TunnelPhase::Pending => RelaySessionPhase::Pending,
            control::TunnelPhase::Active => RelaySessionPhase::Active,
            control::TunnelPhase::Closed => RelaySessionPhase::Closed,
        };
        let metadata = |endpoint_side| RelayConnectionMetadata {
            session_id: runtime.session_id,
            user_id: runtime.user_id.clone(),
            username: username.clone(),
            target_id: runtime.target_id.clone(),
            target_name: target_name.clone(),
            endpoint_side,
            session_phase,
        };
        metadata_by_endpoint.insert(client_endpoint_id, metadata(RelayEndpointSide::Client));
        if let Some(target_data_endpoint_id) = target_data_endpoint_id {
            metadata_by_endpoint
                .insert(target_data_endpoint_id, metadata(RelayEndpointSide::Target));
        }
    }

    let connections = after
        .connections
        .into_iter()
        .map(|connection| {
            let endpoint_id = connection.endpoint_id.to_string();
            let connection_id = connection.connection_id.as_u64();
            let (previous_received, previous_sent) = before_by_connection
                .get(&(endpoint_id.clone(), connection_id))
                .copied()
                .unwrap_or_default();
            RelayConnectionView {
                endpoint_id: endpoint_id.clone(),
                connection_id,
                connected_at_unix_ms: connection
                    .connected_at
                    .duration_since(UNIX_EPOCH)
                    .expect("relay connection timestamps follow the Unix epoch")
                    .as_millis() as u64,
                active: connection.active,
                bytes_received: connection.bytes_received,
                bytes_sent: connection.bytes_sent,
                bytes_received_per_second: traffic_rate(
                    previous_received,
                    connection.bytes_received,
                    sample_duration,
                ),
                bytes_sent_per_second: traffic_rate(
                    previous_sent,
                    connection.bytes_sent,
                    sample_duration,
                ),
                metadata: metadata_by_endpoint.get(&endpoint_id).cloned(),
            }
        })
        .collect::<Vec<_>>();
    let ssh_session_count = connections
        .iter()
        .filter_map(|connection| {
            connection
                .metadata
                .as_ref()
                .map(|metadata| metadata.session_id)
        })
        .collect::<HashSet<_>>()
        .len() as u64;

    Ok(RelayTrafficView {
        enabled: true,
        sample_duration_ms: sample_duration.as_millis() as u64,
        bytes_received: after.bytes_received,
        bytes_sent: after.bytes_sent,
        bytes_received_per_second: traffic_rate(
            before.bytes_received,
            after.bytes_received,
            sample_duration,
        ),
        bytes_sent_per_second: traffic_rate(before.bytes_sent, after.bytes_sent, sample_duration),
        relay_connection_count: connections.len() as u64,
        ssh_session_count,
        connections,
    })
}

async fn close_relay_session(
    state: &ServerState,
    actor_user_id: String,
    session_id: Uuid,
) -> Result<AdminResponse, ApiError> {
    let runtime = state
        .inner
        .tunnels
        .read()
        .await
        .get(&session_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("live SSH session was not found"))?;
    if runtime.route_mode != crate::protocol::RouteMode::PrivateRelay {
        return Err(ApiError::conflict(
            "admin relay close accepts PrivateRelay sessions only",
        ));
    }
    let Some(relay_clients) = state.inner.relay_clients.read().await.clone() else {
        return Err(ApiError::conflict("private relay is disabled"));
    };

    let mut phase = runtime.phase.lock().await;
    if *phase == control::TunnelPhase::Closed {
        return Err(ApiError::conflict("SSH session is already closing"));
    }
    let (client_endpoint_id, target_data_endpoint_id) = control::relay_endpoint_ids(&runtime).await;
    let mut endpoint_ids = vec![client_endpoint_id.clone()];
    if let Some(target_data_endpoint_id) = target_data_endpoint_id
        && target_data_endpoint_id != client_endpoint_id
    {
        endpoint_ids.push(target_data_endpoint_id);
    }
    let parsed_endpoint_ids = endpoint_ids
        .iter()
        .map(|endpoint_id| {
            endpoint_id
                .parse::<iroh::EndpointId>()
                .expect("relay endpoint ids were validated during tunnel setup")
        })
        .collect::<Vec<_>>();
    let disconnected_relay_connections = relay_clients
        .traffic_snapshot()
        .connections
        .iter()
        .filter(|connection| endpoint_ids.contains(&connection.endpoint_id.to_string()))
        .count() as u64;

    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query("SELECT status, client_endpoint_id FROM tunnel_sessions WHERE id = ?1")
        .bind(session_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::not_found("SSH session was not found"))?;
    let status: String = row.try_get("status")?;
    let stored_client_endpoint_id: String = row.try_get("client_endpoint_id")?;
    if stored_client_endpoint_id != runtime.client_endpoint_id {
        return Err(ApiError::conflict("SSH session endpoint identity changed"));
    }
    if status != "pending" && status != "active" {
        return Err(ApiError::conflict("SSH session is already closed"));
    }

    let operation = AdminOperation::CloseRelaySession { session_id };
    let mut audit = prepare_audit_event(actor_user_id, &operation, &mut tx).await?;
    let updated = sqlx::query(
        "UPDATE tunnel_sessions SET status = 'closed', closed_at = ?1 \
         WHERE id = ?2 AND status IN ('pending', 'active')",
    )
    .bind(unix_time())
    .bind(session_id.to_string())
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "SSH session stopped before it could be closed",
        ));
    }
    let response = AdminResponse::RelaySessionClosed {
        session_id,
        disconnected_relay_connections,
    };
    complete_audit_event(&mut audit, &response);
    insert_audit_event(&mut tx, audit).await?;
    tx.commit().await?;

    *phase = control::TunnelPhase::Closed;
    drop(phase);
    for endpoint_id in parsed_endpoint_ids {
        relay_clients.disconnect(endpoint_id, None);
    }
    let connections_closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if relay_clients
                .traffic_snapshot()
                .connections
                .iter()
                .all(|connection| !endpoint_ids.contains(&connection.endpoint_id.to_string()))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    control::notify_tunnel_closed(state, &runtime, "closed by administrator").await;
    if !connections_closed {
        return Err(ApiError::internal(
            "relay endpoint connections remained after close",
        ));
    }
    Ok(response)
}

fn traffic_rate(before: u64, after: u64, elapsed: Duration) -> f64 {
    (after - before) as f64 / elapsed.as_secs_f64()
}

async fn apply_operation_write(
    state: &ServerState,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    operation: AdminOperation,
) -> Result<AdminResponse, ApiError> {
    use AdminOperation as Op;
    match operation {
        Op::ListUsers
        | Op::ListKeys { .. }
        | Op::ListRoles
        | Op::ListUserRoles { .. }
        | Op::ListRoleGrants { .. }
        | Op::ListApiTokens { .. }
        | Op::ListTargets
        | Op::ListRelayTraffic
        | Op::CloseRelaySession { .. } => {
            unreachable!("special operations are dispatched before the transaction")
        }
        Op::CreateUser { username } => {
            let username = normalize_username(&username)?;
            let id = username.clone();
            let now = unix_time();
            sqlx::query(
                "INSERT INTO users(id, username, enabled, created_at, updated_at) \
                 VALUES (?1, ?2, 1, ?3, ?3)",
            )
            .bind(&id)
            .bind(&username)
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(map_constraint)?;
            Ok(AdminResponse::User(UserView {
                user_id: id,
                username,
                enabled: true,
            }))
        }
        Op::SetUserEnabled { user_id, enabled } => {
            let now = unix_time();
            let changed =
                sqlx::query("UPDATE users SET enabled = ?1, updated_at = ?2 WHERE id = ?3")
                    .bind(i64::from(enabled))
                    .bind(now)
                    .bind(&user_id)
                    .execute(&mut **tx)
                    .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            if !enabled {
                revoke_user_sessions(tx, &user_id, now).await?;
            }
            ensure_admin_remains(tx).await?;
            Ok(AdminResponse::Ok)
        }
        Op::CreateApiToken {
            user_id,
            label,
            expires_in_secs,
        } => {
            let label = normalize_name(&label, "API token label")?;
            let token_id = Uuid::new_v4();
            let now = unix_time();
            let expires_at = expires_in_secs
                .map(|seconds| {
                    if seconds == 0 {
                        return Err(ApiError::bad_request(
                            "API token expiry must be a positive number of seconds",
                        ));
                    }
                    let seconds = i64::try_from(seconds).map_err(|_| {
                        ApiError::bad_request("API token expiry exceeds the supported range")
                    })?;
                    now.checked_add(seconds).ok_or_else(|| {
                        ApiError::bad_request("API token expiry exceeds the supported range")
                    })
                })
                .transpose()?;
            let claims = crate::protocol::ApiTokenClaims {
                sub: user_id.clone(),
                jti: token_id,
                iss: state.inner.issuer.clone(),
                aud: crate::identity::API_TOKEN_AUDIENCE.to_owned(),
                iat: now as u64,
                exp: expires_at.map(|expires_at| expires_at as u64),
            };
            let token = crate::identity::encode_api_token(
                &claims,
                &state.inner.keys.user_access.private_key_pem,
            )
            .map_err(ApiError::from)?;
            let inserted = sqlx::query(
                "INSERT INTO api_tokens(id, user_id, token_hash, label, created_at, expires_at) \
                 SELECT ?1, id, ?3, ?4, ?5, ?6 FROM users WHERE id = ?2 AND enabled = 1",
            )
            .bind(token_id.to_string())
            .bind(&user_id)
            .bind(hash_secret(&token))
            .bind(&label)
            .bind(now)
            .bind(expires_at)
            .execute(&mut **tx)
            .await
            .map_err(map_constraint)?;
            if inserted.rows_affected() != 1 {
                return Err(ApiError::not_found("enabled user does not exist"));
            }
            Ok(AdminResponse::ApiTokenIssued {
                api_token: ApiTokenView {
                    token_id,
                    user_id,
                    label,
                    created_at: now,
                    expires_at,
                    revoked_at: None,
                },
                token,
            })
        }
        Op::RevokeApiToken { token_id } => {
            let now = unix_time();
            let changed = sqlx::query(
                "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE id = ?2",
            )
            .bind(now)
            .bind(token_id.to_string())
            .execute(&mut **tx)
            .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("API token does not exist"));
            }
            Ok(AdminResponse::Ok)
        }
        Op::AddUserKey {
            user_id,
            public_key,
            label,
        } => {
            if label.trim().is_empty() || label.len() > 128 {
                return Err(ApiError::bad_request("key label must be 1 to 128 bytes"));
            }
            let canonical = canonical_ssh_key(&public_key)?;
            let fingerprint = ssh_fingerprint(&canonical)?;
            let key_id = Uuid::new_v4();
            let now = unix_time();
            let inserted = sqlx::query(
                "INSERT INTO user_keys(id, user_id, public_key, fingerprint, label, enabled, created_at) \
                 SELECT ?1, id, ?3, ?4, ?5, 1, ?6 FROM users WHERE id = ?2",
            )
            .bind(key_id.to_string())
            .bind(&user_id)
            .bind(canonical.clone())
            .bind(fingerprint)
            .bind(label.trim())
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(map_constraint)?;
            if inserted.rows_affected() != 1 {
                return Err(ApiError::not_found("user does not exist"));
            }
            Ok(AdminResponse::Keys(vec![UserKeyView {
                key_id,
                user_id,
                public_key: canonical,
                label: label.trim().to_owned(),
            }]))
        }
        Op::RemoveUserKey { key_id } => {
            let result = sqlx::query("UPDATE user_keys SET enabled = 0 WHERE id = ?1")
                .bind(key_id.to_string())
                .execute(&mut **tx)
                .await?;
            if result.rows_affected() == 0 {
                return Err(ApiError::not_found("SSH key does not exist"));
            }
            Ok(AdminResponse::Ok)
        }
        Op::CreateRole { name } => {
            let name = normalize_name(&name, "role")?;
            let role_id = name.to_ascii_lowercase();
            sqlx::query("INSERT INTO roles(id, name, built_in, created_at) VALUES (?1, ?2, 0, ?3)")
                .bind(&role_id)
                .bind(&name)
                .bind(unix_time())
                .execute(&mut **tx)
                .await
                .map_err(map_constraint)?;
            Ok(AdminResponse::Role(RoleView { role_id, name }))
        }
        Op::DeleteRole { role_id } => {
            let built_in = sqlx::query_scalar::<_, i64>("SELECT built_in FROM roles WHERE id = ?1")
                .bind(&role_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| ApiError::not_found("role does not exist"))?;
            if built_in != 0 {
                return Err(ApiError::forbidden());
            }
            sqlx::query("DELETE FROM roles WHERE id = ?1")
                .bind(&role_id)
                .execute(&mut **tx)
                .await?;
            ensure_admin_remains(tx).await?;
            Ok(AdminResponse::Ok)
        }
        Op::SetUserRoles { user_id, role_ids } => {
            let user_exists =
                sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)")
                    .bind(&user_id)
                    .fetch_one(&mut **tx)
                    .await?;
            if user_exists == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            sqlx::query("DELETE FROM user_roles WHERE user_id = ?1")
                .bind(&user_id)
                .execute(&mut **tx)
                .await?;
            for role_id in role_ids.iter().collect::<std::collections::BTreeSet<_>>() {
                let inserted = sqlx::query("INSERT INTO user_roles(user_id, role_id) SELECT ?1, id FROM roles WHERE id = ?2")
                    .bind(&user_id)
                    .bind(role_id)
                    .execute(&mut **tx)
                    .await?;
                if inserted.rows_affected() != 1 {
                    return Err(ApiError::not_found("role does not exist"));
                }
            }
            ensure_admin_remains(tx).await?;
            let roles = list_user_roles_tx(tx, &user_id).await?;
            Ok(AdminResponse::UserRoles(roles))
        }
        Op::GrantTarget {
            role_id,
            target_id,
            permission,
        } => {
            ensure_permission(permission);
            let inserted = sqlx::query(
                "INSERT INTO target_permissions(role_id, target_id, permission) \
                 SELECT r.id, t.id, 'ssh_connect' FROM roles r, targets t \
                 WHERE r.id = ?1 AND t.id = ?2 AND t.deleted_at IS NULL",
            )
            .bind(&role_id)
            .bind(&target_id)
            .execute(&mut **tx)
            .await
            .map_err(map_constraint)?;
            if inserted.rows_affected() != 1 {
                return Err(ApiError::not_found("role or target does not exist"));
            }
            Ok(AdminResponse::Ok)
        }
        Op::RevokeTarget {
            role_id,
            target_id,
            permission,
        } => {
            ensure_permission(permission);
            sqlx::query("DELETE FROM target_permissions WHERE role_id = ?1 AND target_id = ?2 AND permission = 'ssh_connect'")
                .bind(&role_id)
                .bind(&target_id)
                .execute(&mut **tx)
                .await?;
            Ok(AdminResponse::Ok)
        }
        Op::CreateTarget { name } => {
            let name = normalize_target_name(&name)?;
            let target_id = name.to_ascii_lowercase();
            let enrollment_token = new_secret();
            let now = unix_time();
            sqlx::query(
                "INSERT INTO targets(id, name, enabled, enrollment_token_hash, enrollment_expires_at, created_at, updated_at) \
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?5)",
            )
            .bind(&target_id)
            .bind(&name)
            .bind(hash_secret(&enrollment_token))
            .bind(now + 10 * 60)
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(map_constraint)?;
            Ok(AdminResponse::TargetCreated {
                target: TargetView {
                    target_id,
                    name,
                    enabled: true,
                    online: false,
                },
                enrollment_token,
            })
        }
        Op::RenameTarget { target_id, name } => {
            let name = normalize_target_name(&name)?;
            let changed = sqlx::query("UPDATE targets SET name = ?1, updated_at = ?2 WHERE id = ?3 AND deleted_at IS NULL")
                .bind(name)
                .bind(unix_time())
                .bind(&target_id)
                .execute(&mut **tx)
                .await
                .map_err(map_constraint)?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("target does not exist"));
            }
            Ok(AdminResponse::Ok)
        }
        Op::SetTargetEnabled { target_id, enabled } => {
            let changed = sqlx::query("UPDATE targets SET enabled = ?1, updated_at = ?2 WHERE id = ?3 AND deleted_at IS NULL")
                .bind(i64::from(enabled))
                .bind(unix_time())
                .bind(&target_id)
                .execute(&mut **tx)
                .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("target does not exist"));
            }
            Ok(AdminResponse::Ok)
        }
        Op::DeleteTarget { target_id } => {
            let changed = sqlx::query("UPDATE targets SET enabled = 0, deleted_at = COALESCE(deleted_at, ?1), updated_at = ?1 WHERE id = ?2")
                .bind(unix_time())
                .bind(&target_id)
                .execute(&mut **tx)
                .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("target does not exist"));
            }
            Ok(AdminResponse::Ok)
        }
        Op::IssueEnrollment { target_id } => {
            let enrollment_token = new_secret();
            let now = unix_time();
            let changed = sqlx::query(
                "UPDATE targets SET enrollment_token_hash = ?1, enrollment_expires_at = ?2, updated_at = ?3 \
                 WHERE id = ?4 AND deleted_at IS NULL",
            )
            .bind(hash_secret(&enrollment_token))
            .bind(now + 10 * 60)
            .bind(now)
            .bind(&target_id)
            .execute(&mut **tx)
            .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("target does not exist"));
            }
            Ok(AdminResponse::EnrollmentIssued {
                target_id,
                enrollment_token,
            })
        }
    }
}

struct AuditEvent {
    id: Uuid,
    occurred_at: i64,
    actor_user_id: String,
    operation: &'static str,
    object_type: &'static str,
    object_id: Option<String>,
    context: serde_json::Value,
}

async fn prepare_audit_event(
    actor_user_id: String,
    operation: &AdminOperation,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<AuditEvent, ApiError> {
    use AdminOperation as Op;

    let (name, object_type, object_id, context) = match operation {
        Op::CreateUser { username, .. } => (
            "create_user",
            "user",
            None,
            serde_json::json!({ "username": username }),
        ),
        Op::CreateApiToken {
            user_id,
            label,
            expires_in_secs,
        } => (
            "create_api_token",
            "api_token",
            None,
            serde_json::json!({
                "user_id": user_id,
                "label": label.trim(),
                "expires_in_secs": expires_in_secs,
            }),
        ),
        Op::RevokeApiToken { token_id } => {
            let row = sqlx::query("SELECT user_id, label FROM api_tokens WHERE id = ?1")
                .bind(token_id.to_string())
                .fetch_optional(&mut **tx)
                .await?;
            (
                "revoke_api_token",
                "api_token",
                Some(token_id.to_string()),
                serde_json::json!({
                    "token_id": token_id,
                    "user_id": row.as_ref().map(|row| row.try_get::<String, _>("user_id")).transpose()?,
                    "label": row.as_ref().map(|row| row.try_get::<String, _>("label")).transpose()?,
                }),
            )
        }
        Op::SetUserEnabled { user_id, enabled } => {
            ("set_user_enabled", "user", Some(user_id.clone()), {
                let row = sqlx::query("SELECT username, enabled FROM users WHERE id = ?1")
                    .bind(user_id)
                    .fetch_optional(&mut **tx)
                    .await?;
                serde_json::json!({
                    "user_id": user_id,
                    "username": row.as_ref().map(|row| row.try_get::<String, _>("username")).transpose()?,
                    "previous_enabled": row.as_ref().map(|row| row.try_get::<i64, _>("enabled").map(|enabled| enabled == 1)).transpose()?,
                    "enabled": enabled,
                })
            })
        }
        Op::AddUserKey { user_id, label, .. } => (
            "add_user_key",
            "ssh_key",
            None,
            serde_json::json!({ "user_id": user_id, "label": label.trim() }),
        ),
        Op::RemoveUserKey { key_id } => {
            let details = sqlx::query("SELECT user_id, label FROM user_keys WHERE id = ?1")
                .bind(key_id.to_string())
                .fetch_optional(&mut **tx)
                .await?
                .map(|row| -> Result<serde_json::Value, sqlx::Error> {
                    Ok(serde_json::json!({
                        "key_id": key_id,
                        "user_id": row.try_get::<String, _>("user_id")?,
                        "label": row.try_get::<String, _>("label")?,
                    }))
                })
                .transpose()?;
            (
                "remove_user_key",
                "ssh_key",
                Some(key_id.to_string()),
                details.unwrap_or_else(|| serde_json::json!({ "key_id": key_id })),
            )
        }
        Op::CreateRole { name } => (
            "create_role",
            "role",
            None,
            serde_json::json!({ "name": name }),
        ),
        Op::DeleteRole { role_id } => {
            let role_name = sqlx::query_scalar::<_, String>("SELECT name FROM roles WHERE id = ?1")
                .bind(role_id)
                .fetch_optional(&mut **tx)
                .await?;
            let user_ids = sqlx::query_scalar::<_, String>(
                "SELECT user_id FROM user_roles WHERE role_id = ?1 ORDER BY user_id",
            )
            .bind(role_id)
            .fetch_all(&mut **tx)
            .await?;
            let grant_rows = sqlx::query(
                "SELECT target_id, permission FROM target_permissions WHERE role_id = ?1 ORDER BY target_id, permission",
            )
            .bind(role_id)
            .fetch_all(&mut **tx)
            .await?;
            let grants = grant_rows
                .into_iter()
                .map(|row| {
                    Ok(serde_json::json!({
                        "target_id": row.try_get::<String, _>("target_id")?,
                        "permission": row.try_get::<String, _>("permission")?,
                    }))
                })
                .collect::<Result<Vec<_>, sqlx::Error>>()?;
            (
                "delete_role",
                "role",
                Some(role_id.clone()),
                serde_json::json!({
                    "role_id": role_id,
                    "role_name": role_name,
                    "user_ids": user_ids,
                    "grants": grants,
                }),
            )
        }
        Op::SetUserRoles { user_id, role_ids } => {
            let previous_role_ids = sqlx::query_scalar::<_, String>(
                "SELECT role_id FROM user_roles WHERE user_id = ?1 ORDER BY role_id",
            )
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await?;
            let next_role_ids = role_ids.clone();
            (
                "set_user_roles",
                "user",
                Some(user_id.clone()),
                serde_json::json!({
                    "user_id": user_id,
                    "previous_role_ids": previous_role_ids,
                    "requested_role_ids": next_role_ids,
                }),
            )
        }
        Op::GrantTarget {
            role_id,
            target_id,
            permission,
        } => (
            "grant_target",
            "role_target_permission",
            Some(target_id.clone()),
            serde_json::json!({
                "role_id": role_id,
                "target_id": target_id,
                "permission": permission_name(*permission),
            }),
        ),
        Op::RevokeTarget {
            role_id,
            target_id,
            permission,
        } => (
            "revoke_target",
            "role_target_permission",
            Some(target_id.clone()),
            serde_json::json!({
                "role_id": role_id,
                "target_id": target_id,
                "permission": permission_name(*permission),
            }),
        ),
        Op::CreateTarget { name } => (
            "create_target",
            "target",
            None,
            serde_json::json!({ "name": name }),
        ),
        Op::RenameTarget { target_id, name } => {
            ("rename_target", "target", Some(target_id.clone()), {
                let previous_name = sqlx::query_scalar::<_, String>(
                    "SELECT name FROM targets WHERE id = ?1 AND deleted_at IS NULL",
                )
                .bind(target_id)
                .fetch_optional(&mut **tx)
                .await?;
                serde_json::json!({
                    "target_id": target_id,
                    "previous_name": previous_name,
                    "name": normalize_target_name(name)?,
                })
            })
        }
        Op::SetTargetEnabled { target_id, enabled } => {
            ("set_target_enabled", "target", Some(target_id.clone()), {
                let previous_enabled = sqlx::query_scalar::<_, i64>(
                    "SELECT enabled FROM targets WHERE id = ?1 AND deleted_at IS NULL",
                )
                .bind(target_id)
                .fetch_optional(&mut **tx)
                .await?
                .map(|enabled| enabled == 1);
                serde_json::json!({
                    "target_id": target_id,
                    "previous_enabled": previous_enabled,
                    "enabled": enabled,
                })
            })
        }
        Op::DeleteTarget { target_id } => {
            let row = sqlx::query("SELECT name, enabled FROM targets WHERE id = ?1")
                .bind(target_id.to_string())
                .fetch_optional(&mut **tx)
                .await?;
            (
                "delete_target",
                "target",
                Some(target_id.clone()),
                serde_json::json!({
                    "target_id": target_id,
                    "name": row.as_ref().map(|row| row.try_get::<String, _>("name")).transpose()?,
                    "previous_enabled": row.as_ref().map(|row| row.try_get::<i64, _>("enabled").map(|enabled| enabled == 1)).transpose()?,
                }),
            )
        }
        Op::IssueEnrollment { target_id } => (
            "issue_enrollment",
            "target",
            Some(target_id.clone()),
            serde_json::json!({ "target_id": target_id }),
        ),
        Op::CloseRelaySession { session_id } => {
            let row = sqlx::query(
                "SELECT user_id, target_id, client_endpoint_id, target_endpoint_id \
                 FROM tunnel_sessions WHERE id = ?1",
            )
            .bind(session_id.to_string())
            .fetch_one(&mut **tx)
            .await?;
            (
                "close_relay_session",
                "ssh_session",
                Some(session_id.to_string()),
                serde_json::json!({
                    "session_id": session_id,
                    "user_id": row.try_get::<String, _>("user_id")?,
                    "target_id": row.try_get::<String, _>("target_id")?,
                    "client_endpoint_id": row.try_get::<String, _>("client_endpoint_id")?,
                    "target_endpoint_id": row.try_get::<String, _>("target_endpoint_id")?,
                }),
            )
        }
        Op::ListUsers
        | Op::ListKeys { .. }
        | Op::ListRoles
        | Op::ListUserRoles { .. }
        | Op::ListRoleGrants { .. }
        | Op::ListApiTokens { .. }
        | Op::ListTargets
        | Op::ListRelayTraffic => {
            unreachable!("read operations are dispatched before the transaction")
        }
    };

    Ok(AuditEvent {
        id: Uuid::new_v4(),
        occurred_at: unix_time(),
        actor_user_id,
        operation: name,
        object_type,
        object_id,
        context,
    })
}

fn complete_audit_event(event: &mut AuditEvent, response: &AdminResponse) {
    match (event.operation, response) {
        ("create_user", AdminResponse::User(user)) => {
            event.object_id = Some(user.user_id.clone());
            event.context["username"] = serde_json::json!(user.username);
        }
        ("create_api_token", AdminResponse::ApiTokenIssued { api_token, .. }) => {
            event.object_id = Some(api_token.token_id.to_string());
            event.context["token_id"] = serde_json::json!(api_token.token_id);
            event.context["user_id"] = serde_json::json!(api_token.user_id);
            event.context["label"] = serde_json::json!(api_token.label);
        }
        ("add_user_key", AdminResponse::Keys(keys)) => {
            let key = keys.first().expect("adding one key returns that key");
            event.object_id = Some(key.key_id.to_string());
            event.context["key_id"] = serde_json::json!(key.key_id);
        }
        ("create_role", AdminResponse::Role(role)) => {
            event.object_id = Some(role.role_id.clone());
            event.context["name"] = serde_json::json!(role.name);
        }
        ("create_target", AdminResponse::TargetCreated { target, .. }) => {
            event.object_id = Some(target.target_id.clone());
            event.context["name"] = serde_json::json!(target.name);
        }
        ("set_user_roles", AdminResponse::UserRoles(roles)) => {
            event.context["role_ids"] = serde_json::json!(
                roles
                    .iter()
                    .map(|role| role.role_id.clone())
                    .collect::<Vec<_>>()
            );
        }
        (
            "close_relay_session",
            AdminResponse::RelaySessionClosed {
                disconnected_relay_connections,
                ..
            },
        ) => {
            event.context["disconnected_relay_connections"] =
                serde_json::json!(disconnected_relay_connections);
        }
        _ => {}
    }
}

fn permission_name(permission: TargetPermission) -> &'static str {
    match permission {
        TargetPermission::SshConnect => "ssh_connect",
    }
}

async fn list_users(state: &ServerState) -> Result<Vec<UserView>, ApiError> {
    let rows =
        sqlx::query("SELECT id, username, enabled FROM users ORDER BY username COLLATE NOCASE")
            .fetch_all(&state.inner.db.pool)
            .await?;
    rows.into_iter()
        .map(|row| {
            Ok(UserView {
                user_id: row.try_get("id")?,
                username: row.try_get("username")?,
                enabled: row.try_get::<i64, _>("enabled")? == 1,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_api_tokens(
    state: &ServerState,
    user_id: &str,
) -> Result<Vec<ApiTokenView>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, user_id, label, created_at, expires_at, revoked_at FROM api_tokens \
         WHERE user_id = ?1 ORDER BY created_at, id",
    )
    .bind(user_id)
    .fetch_all(&state.inner.db.pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ApiTokenView {
                token_id: row_uuid(&row, "id")?,
                user_id: row.try_get("user_id")?,
                label: row.try_get("label")?,
                created_at: row.try_get("created_at")?,
                expires_at: row.try_get("expires_at")?,
                revoked_at: row.try_get("revoked_at")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn get_user(state: &ServerState, user_id: &str) -> Result<UserView, ApiError> {
    let row = sqlx::query("SELECT id, username, enabled FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_optional(&state.inner.db.pool)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(UserView {
        user_id: user_id.to_owned(),
        username: row.try_get("username")?,
        enabled: row.try_get::<i64, _>("enabled")? == 1,
    })
}

async fn list_roles(state: &ServerState) -> Result<Vec<RoleView>, ApiError> {
    let rows = sqlx::query("SELECT id, name FROM roles ORDER BY name COLLATE NOCASE")
        .fetch_all(&state.inner.db.pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(RoleView {
                role_id: row.try_get("id")?,
                name: row.try_get("name")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_user_roles(state: &ServerState, user_id: &str) -> Result<Vec<RoleView>, ApiError> {
    let mut tx = state.inner.db.pool.begin().await?;
    let roles = list_user_roles_tx(&mut tx, user_id).await?;
    tx.commit().await?;
    Ok(roles)
}

async fn list_user_roles_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
) -> Result<Vec<RoleView>, ApiError> {
    let rows = sqlx::query("SELECT r.id, r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?1 ORDER BY r.name COLLATE NOCASE")
        .bind(user_id)
        .fetch_all(&mut **tx)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(RoleView {
                role_id: row.try_get("id")?,
                name: row.try_get("name")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_keys(state: &ServerState, user_id: &str) -> Result<Vec<UserKeyView>, ApiError> {
    let rows = sqlx::query("SELECT id, user_id, public_key, label FROM user_keys WHERE user_id = ?1 AND enabled = 1 ORDER BY created_at")
        .bind(user_id)
        .fetch_all(&state.inner.db.pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(UserKeyView {
                key_id: row_uuid(&row, "id")?,
                user_id: row.try_get("user_id")?,
                public_key: row.try_get("public_key")?,
                label: row.try_get("label")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_role_grants(
    state: &ServerState,
    role_id: &str,
) -> Result<Vec<RoleGrantView>, ApiError> {
    let rows = sqlx::query("SELECT role_id, target_id, permission FROM target_permissions WHERE role_id = ?1 ORDER BY target_id")
        .bind(role_id)
        .fetch_all(&state.inner.db.pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            let permission: String = row.try_get("permission").map_err(ApiError::from)?;
            let permission = match permission.as_str() {
                "ssh_connect" => TargetPermission::SshConnect,
                _ => return Err(ApiError::internal("unknown permission stored in database")),
            };
            Ok(RoleGrantView {
                role_id: row.try_get("role_id").map_err(ApiError::from)?,
                target_id: row.try_get("target_id").map_err(ApiError::from)?,
                permission,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_targets(state: &ServerState) -> Result<Vec<TargetView>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, name, enabled FROM targets WHERE deleted_at IS NULL ORDER BY name COLLATE NOCASE",
    )
    .fetch_all(&state.inner.db.pool)
    .await?;
    let online = state.inner.online_agents.read().await;
    rows.into_iter()
        .map(|row| {
            let target_id = row.try_get("id")?;
            let online = online.contains_key(&target_id);
            Ok(TargetView {
                target_id,
                name: row.try_get("name")?,
                enabled: row.try_get::<i64, _>("enabled")? == 1,
                online,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn revoke_user_sessions(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
    now: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?1) WHERE user_id = ?2",
    )
    .bind(now)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE session_id IN (SELECT id FROM auth_sessions WHERE user_id = ?2)")
        .bind(now)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn ensure_admin_remains(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), ApiError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT u.id) FROM users u \
         JOIN user_roles ur ON ur.user_id = u.id \
         JOIN role_global_permissions gp ON gp.role_id = ur.role_id \
         WHERE u.enabled = 1 AND gp.permission = 'admin'",
    )
    .fetch_one(&mut **tx)
    .await?;
    if count == 0 {
        return Err(ApiError::conflict(
            "at least one enabled administrator must remain",
        ));
    }
    Ok(())
}

fn ensure_permission(permission: TargetPermission) {
    match permission {
        TargetPermission::SshConnect => {}
    }
}

fn normalize_username(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || !value.is_ascii()
        || value.len() > 64
        || value.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "username must be 1 to 64 printable ASCII bytes",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_role_id(value: &str) -> Result<String, ApiError> {
    Ok(normalize_name(value, "role")?.to_ascii_lowercase())
}

pub(super) fn normalize_target_id(value: &str) -> Result<String, ApiError> {
    Ok(normalize_target_name(value)?.to_ascii_lowercase())
}

fn normalize_target_name(value: &str) -> Result<String, ApiError> {
    let value = normalize_name(value, "target")?;
    let valid = value.len() <= 64
        && value.is_ascii()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        return Err(ApiError::bad_request(
            "target name must be a 1 to 64 character ASCII slug",
        ));
    }
    Ok(value)
}

fn normalize_name(value: &str, kind: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request(format!(
            "{kind} name must be 1 to 128 printable bytes"
        )));
    }
    Ok(value.to_owned())
}

fn map_constraint(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.is_unique_violation() {
            return ApiError::conflict("an item with this name or key already exists");
        }
        if db_error.is_foreign_key_violation() {
            return ApiError::not_found("referenced user, role or target does not exist");
        }
    }
    ApiError::from(error)
}
