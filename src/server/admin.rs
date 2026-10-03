use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use sqlx::Row;
use uuid::Uuid;

use crate::protocol::{
    AdminOperation, AdminRequest, AdminResponse, MeView, RoleGrantView, RoleView, TargetPermission,
    TargetView, UserKeyView, UserView,
};

use super::auth::{
    authenticate, canonical_ssh_key, password_hash_limited, ssh_fingerprint, validate_password,
};
use super::db::{row_uuid, unix_time};
use super::error::ApiError;
use super::{ServerState, hash_secret, new_secret};

pub(crate) async fn me(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<MeView>, ApiError> {
    let user = authenticate(&state, &headers).await?;
    let user_view = get_user(&state, user.user_id).await?;
    let roles = list_user_roles(&state, user.user_id).await?;
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
    .bind(user.user_id.to_string())
    .fetch_all(&state.inner.db.pool)
    .await?;
    let online = state.inner.online_agents.read().await;
    let views = rows
        .into_iter()
        .map(|row| {
            let id = row_uuid(&row, "id")?;
            Ok(TargetView {
                target_id: id,
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
    if !state.inner.db.is_admin(actor.user_id).await? {
        return Err(ApiError::forbidden());
    }
    Ok(Json(
        apply_operation(&state, actor.user_id, request.operation).await?,
    ))
}

pub(crate) async fn apply_operation(
    state: &ServerState,
    actor_user_id: Uuid,
    operation: AdminOperation,
) -> Result<AdminResponse, ApiError> {
    use AdminOperation as Op;

    match &operation {
        Op::ListUsers => return Ok(AdminResponse::Users(list_users(state).await?)),
        Op::ListKeys { user_id } => {
            return Ok(AdminResponse::Keys(list_keys(state, *user_id).await?));
        }
        Op::ListRoles => return Ok(AdminResponse::Roles(list_roles(state).await?)),
        Op::ListUserRoles { user_id } => {
            return Ok(AdminResponse::UserRoles(
                list_user_roles(state, *user_id).await?,
            ));
        }
        Op::ListRoleGrants { role_id } => {
            return Ok(AdminResponse::Grants(
                list_role_grants(state, *role_id).await?,
            ));
        }
        Op::ListTargets => return Ok(AdminResponse::Targets(list_targets(state).await?)),
        _ => {}
    }

    let mut operation = operation;
    let password_hash = match &mut operation {
        Op::CreateUser { password, .. } | Op::ResetPassword { password, .. } => {
            validate_password(password)?;
            Some(
                password_hash_limited(std::mem::take(password))
                    .await
                    .map_err(ApiError::from)?,
            )
        }
        _ => None,
    };
    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let mut audit = prepare_audit_event(actor_user_id, &operation, &mut tx).await?;
    let response = apply_operation_write(&mut tx, password_hash, operation).await?;
    complete_audit_event(&mut audit, &response);
    sqlx::query(
        "INSERT INTO admin_audit(id, occurred_at, actor_user_id, operation, object_type, object_id, context_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(audit.id.to_string())
    .bind(audit.occurred_at)
    .bind(audit.actor_user_id.to_string())
    .bind(audit.operation)
    .bind(audit.object_type)
    .bind(audit.object_id.map(|id| id.to_string()))
    .bind(serde_json::to_string(&audit.context).map_err(ApiError::internal)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(response)
}

async fn apply_operation_write(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    password_hash: Option<String>,
    operation: AdminOperation,
) -> Result<AdminResponse, ApiError> {
    use AdminOperation as Op;
    match operation {
        Op::ListUsers
        | Op::ListKeys { .. }
        | Op::ListRoles
        | Op::ListUserRoles { .. }
        | Op::ListRoleGrants { .. }
        | Op::ListTargets => unreachable!("read operations are dispatched before the transaction"),
        Op::CreateUser {
            username,
            password: _,
        } => {
            let username = normalize_username(&username)?;
            let id = Uuid::new_v4();
            let now = unix_time();
            sqlx::query(
                "INSERT INTO users(id, username, password_hash, enabled, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, 1, ?4, ?4)",
            )
            .bind(id.to_string())
            .bind(&username)
            .bind(password_hash.expect("password hash was prepared before opening transaction"))
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
                    .bind(user_id.to_string())
                    .execute(&mut **tx)
                    .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            if !enabled {
                revoke_user_sessions(tx, user_id, now).await?;
            }
            ensure_admin_remains(tx).await?;
            Ok(AdminResponse::Ok)
        }
        Op::ResetPassword {
            user_id,
            password: _,
        } => {
            let password_hash =
                password_hash.expect("password hash was prepared before opening transaction");
            let now = unix_time();
            let changed =
                sqlx::query("UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3")
                    .bind(password_hash)
                    .bind(now)
                    .bind(user_id.to_string())
                    .execute(&mut **tx)
                    .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            revoke_user_sessions(tx, user_id, now).await?;
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
            .bind(user_id.to_string())
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
            let role_id = Uuid::new_v4();
            sqlx::query("INSERT INTO roles(id, name, built_in, created_at) VALUES (?1, ?2, 0, ?3)")
                .bind(role_id.to_string())
                .bind(&name)
                .bind(unix_time())
                .execute(&mut **tx)
                .await
                .map_err(map_constraint)?;
            Ok(AdminResponse::Role(RoleView { role_id, name }))
        }
        Op::DeleteRole { role_id } => {
            let built_in = sqlx::query_scalar::<_, i64>("SELECT built_in FROM roles WHERE id = ?1")
                .bind(role_id.to_string())
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| ApiError::not_found("role does not exist"))?;
            if built_in != 0 {
                return Err(ApiError::forbidden());
            }
            sqlx::query("DELETE FROM roles WHERE id = ?1")
                .bind(role_id.to_string())
                .execute(&mut **tx)
                .await?;
            ensure_admin_remains(tx).await?;
            Ok(AdminResponse::Ok)
        }
        Op::SetUserRoles { user_id, role_ids } => {
            let user_exists =
                sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)")
                    .bind(user_id.to_string())
                    .fetch_one(&mut **tx)
                    .await?;
            if user_exists == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            sqlx::query("DELETE FROM user_roles WHERE user_id = ?1")
                .bind(user_id.to_string())
                .execute(&mut **tx)
                .await?;
            for role_id in role_ids.iter().collect::<std::collections::BTreeSet<_>>() {
                let inserted = sqlx::query("INSERT INTO user_roles(user_id, role_id) SELECT ?1, id FROM roles WHERE id = ?2")
                    .bind(user_id.to_string())
                    .bind(role_id.to_string())
                    .execute(&mut **tx)
                    .await?;
                if inserted.rows_affected() != 1 {
                    return Err(ApiError::not_found("role does not exist"));
                }
            }
            ensure_admin_remains(tx).await?;
            let roles = list_user_roles_tx(tx, user_id).await?;
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
            .bind(role_id.to_string())
            .bind(target_id.to_string())
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
                .bind(role_id.to_string())
                .bind(target_id.to_string())
                .execute(&mut **tx)
                .await?;
            Ok(AdminResponse::Ok)
        }
        Op::CreateTarget { name } => {
            let name = normalize_name(&name, "target")?;
            let target_id = Uuid::new_v4();
            let enrollment_token = new_secret();
            let now = unix_time();
            sqlx::query(
                "INSERT INTO targets(id, name, enabled, enrollment_token_hash, enrollment_expires_at, created_at, updated_at) \
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?5)",
            )
            .bind(target_id.to_string())
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
            let name = normalize_name(&name, "target")?;
            let changed = sqlx::query("UPDATE targets SET name = ?1, updated_at = ?2 WHERE id = ?3 AND deleted_at IS NULL")
                .bind(name)
                .bind(unix_time())
                .bind(target_id.to_string())
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
                .bind(target_id.to_string())
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
                .bind(target_id.to_string())
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
            .bind(target_id.to_string())
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
    actor_user_id: Uuid,
    operation: &'static str,
    object_type: &'static str,
    object_id: Option<Uuid>,
    context: serde_json::Value,
}

async fn prepare_audit_event(
    actor_user_id: Uuid,
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
        Op::SetUserEnabled { user_id, enabled } => ("set_user_enabled", "user", Some(*user_id), {
            let row = sqlx::query("SELECT username, enabled FROM users WHERE id = ?1")
                .bind(user_id.to_string())
                .fetch_optional(&mut **tx)
                .await?;
            serde_json::json!({
                "user_id": user_id,
                "username": row.as_ref().map(|row| row.try_get::<String, _>("username")).transpose()?,
                "previous_enabled": row.as_ref().map(|row| row.try_get::<i64, _>("enabled").map(|enabled| enabled == 1)).transpose()?,
                "enabled": enabled,
            })
        }),
        Op::ResetPassword { user_id, .. } => (
            "reset_password",
            "user",
            Some(*user_id),
            serde_json::json!({ "user_id": user_id }),
        ),
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
                Some(*key_id),
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
                .bind(role_id.to_string())
                .fetch_optional(&mut **tx)
                .await?;
            let user_ids = sqlx::query_scalar::<_, String>(
                "SELECT user_id FROM user_roles WHERE role_id = ?1 ORDER BY user_id",
            )
            .bind(role_id.to_string())
            .fetch_all(&mut **tx)
            .await?;
            let grant_rows = sqlx::query(
                "SELECT target_id, permission FROM target_permissions WHERE role_id = ?1 ORDER BY target_id, permission",
            )
            .bind(role_id.to_string())
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
                Some(*role_id),
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
            .bind(user_id.to_string())
            .fetch_all(&mut **tx)
            .await?;
            let next_role_ids = role_ids.iter().map(Uuid::to_string).collect::<Vec<_>>();
            (
                "set_user_roles",
                "user",
                Some(*user_id),
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
            Some(*target_id),
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
            Some(*target_id),
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
        Op::RenameTarget { target_id, name } => ("rename_target", "target", Some(*target_id), {
            let previous_name = sqlx::query_scalar::<_, String>(
                "SELECT name FROM targets WHERE id = ?1 AND deleted_at IS NULL",
            )
            .bind(target_id.to_string())
            .fetch_optional(&mut **tx)
            .await?;
            serde_json::json!({
                "target_id": target_id,
                "previous_name": previous_name,
                "name": normalize_name(name, "target")?,
            })
        }),
        Op::SetTargetEnabled { target_id, enabled } => {
            ("set_target_enabled", "target", Some(*target_id), {
                let previous_enabled = sqlx::query_scalar::<_, i64>(
                    "SELECT enabled FROM targets WHERE id = ?1 AND deleted_at IS NULL",
                )
                .bind(target_id.to_string())
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
                Some(*target_id),
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
            Some(*target_id),
            serde_json::json!({ "target_id": target_id }),
        ),
        Op::ListUsers
        | Op::ListKeys { .. }
        | Op::ListRoles
        | Op::ListUserRoles { .. }
        | Op::ListRoleGrants { .. }
        | Op::ListTargets => unreachable!("read operations are dispatched before the transaction"),
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
            event.object_id = Some(user.user_id);
            event.context["username"] = serde_json::json!(user.username);
        }
        ("add_user_key", AdminResponse::Keys(keys)) => {
            let key = keys.first().expect("adding one key returns that key");
            event.object_id = Some(key.key_id);
            event.context["key_id"] = serde_json::json!(key.key_id);
        }
        ("create_role", AdminResponse::Role(role)) => {
            event.object_id = Some(role.role_id);
            event.context["name"] = serde_json::json!(role.name);
        }
        ("create_target", AdminResponse::TargetCreated { target, .. }) => {
            event.object_id = Some(target.target_id);
            event.context["name"] = serde_json::json!(target.name);
        }
        ("set_user_roles", AdminResponse::UserRoles(roles)) => {
            event.context["role_ids"] =
                serde_json::json!(roles.iter().map(|role| role.role_id).collect::<Vec<_>>());
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
                user_id: row_uuid(&row, "id")?,
                username: row.try_get("username")?,
                enabled: row.try_get::<i64, _>("enabled")? == 1,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn get_user(state: &ServerState, user_id: Uuid) -> Result<UserView, ApiError> {
    let row = sqlx::query("SELECT id, username, enabled FROM users WHERE id = ?1")
        .bind(user_id.to_string())
        .fetch_optional(&state.inner.db.pool)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(UserView {
        user_id,
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
                role_id: row_uuid(&row, "id")?,
                name: row.try_get("name")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_user_roles(state: &ServerState, user_id: Uuid) -> Result<Vec<RoleView>, ApiError> {
    let mut tx = state.inner.db.pool.begin().await?;
    let roles = list_user_roles_tx(&mut tx, user_id).await?;
    tx.commit().await?;
    Ok(roles)
}

async fn list_user_roles_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: Uuid,
) -> Result<Vec<RoleView>, ApiError> {
    let rows = sqlx::query("SELECT r.id, r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?1 ORDER BY r.name COLLATE NOCASE")
        .bind(user_id.to_string())
        .fetch_all(&mut **tx)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(RoleView {
                role_id: row_uuid(&row, "id")?,
                name: row.try_get("name")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_keys(state: &ServerState, user_id: Uuid) -> Result<Vec<UserKeyView>, ApiError> {
    let rows = sqlx::query("SELECT id, user_id, public_key, label FROM user_keys WHERE user_id = ?1 AND enabled = 1 ORDER BY created_at")
        .bind(user_id.to_string())
        .fetch_all(&state.inner.db.pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(UserKeyView {
                key_id: row_uuid(&row, "id")?,
                user_id: row_uuid(&row, "user_id")?,
                public_key: row.try_get("public_key")?,
                label: row.try_get("label")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn list_role_grants(
    state: &ServerState,
    role_id: Uuid,
) -> Result<Vec<RoleGrantView>, ApiError> {
    let rows = sqlx::query("SELECT role_id, target_id, permission FROM target_permissions WHERE role_id = ?1 ORDER BY target_id")
        .bind(role_id.to_string())
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
                role_id: row_uuid(&row, "role_id").map_err(ApiError::from)?,
                target_id: row_uuid(&row, "target_id").map_err(ApiError::from)?,
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
            let target_id = row_uuid(&row, "id")?;
            Ok(TargetView {
                target_id,
                name: row.try_get("name")?,
                enabled: row.try_get::<i64, _>("enabled")? == 1,
                online: online.contains_key(&target_id),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

async fn revoke_user_sessions(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: Uuid,
    now: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?1) WHERE user_id = ?2",
    )
    .bind(now)
    .bind(user_id.to_string())
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE session_id IN (SELECT id FROM auth_sessions WHERE user_id = ?2)")
        .bind(now)
        .bind(user_id.to_string())
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
