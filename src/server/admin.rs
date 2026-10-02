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
    Ok(Json(apply_operation(&state, request.operation).await?))
}

pub(crate) async fn apply_operation(
    state: &ServerState,
    operation: AdminOperation,
) -> Result<AdminResponse, ApiError> {
    use AdminOperation as Op;
    match operation {
        Op::ListUsers => Ok(AdminResponse::Users(list_users(state).await?)),
        Op::CreateUser { username, password } => {
            let username = normalize_username(&username)?;
            validate_password(&password)?;
            let id = Uuid::new_v4();
            let now = unix_time();
            sqlx::query(
                "INSERT INTO users(id, username, password_hash, enabled, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, 1, ?4, ?4)",
            )
            .bind(id.to_string())
            .bind(&username)
            .bind(
                password_hash_limited(password)
                    .await
                    .map_err(ApiError::from)?,
            )
            .bind(now)
            .execute(&state.inner.db.pool)
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
            let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
            let changed =
                sqlx::query("UPDATE users SET enabled = ?1, updated_at = ?2 WHERE id = ?3")
                    .bind(i64::from(enabled))
                    .bind(now)
                    .bind(user_id.to_string())
                    .execute(&mut *tx)
                    .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            if !enabled {
                revoke_user_sessions(&mut tx, user_id, now).await?;
            }
            ensure_admin_remains(&mut tx).await?;
            tx.commit().await?;
            Ok(AdminResponse::Ok)
        }
        Op::ResetPassword { user_id, password } => {
            validate_password(&password)?;
            let password_hash = password_hash_limited(password)
                .await
                .map_err(ApiError::from)?;
            let now = unix_time();
            let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
            let changed =
                sqlx::query("UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3")
                    .bind(password_hash)
                    .bind(now)
                    .bind(user_id.to_string())
                    .execute(&mut *tx)
                    .await?;
            if changed.rows_affected() == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            revoke_user_sessions(&mut tx, user_id, now).await?;
            tx.commit().await?;
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
            .execute(&state.inner.db.pool)
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
                .execute(&state.inner.db.pool)
                .await?;
            if result.rows_affected() == 0 {
                return Err(ApiError::not_found("SSH key does not exist"));
            }
            Ok(AdminResponse::Ok)
        }
        Op::ListKeys { user_id } => Ok(AdminResponse::Keys(list_keys(state, user_id).await?)),
        Op::ListRoles => Ok(AdminResponse::Roles(list_roles(state).await?)),
        Op::CreateRole { name } => {
            let name = normalize_name(&name, "role")?;
            let role_id = Uuid::new_v4();
            sqlx::query("INSERT INTO roles(id, name, built_in, created_at) VALUES (?1, ?2, 0, ?3)")
                .bind(role_id.to_string())
                .bind(&name)
                .bind(unix_time())
                .execute(&state.inner.db.pool)
                .await
                .map_err(map_constraint)?;
            Ok(AdminResponse::Role(RoleView { role_id, name }))
        }
        Op::DeleteRole { role_id } => {
            let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
            let built_in = sqlx::query_scalar::<_, i64>("SELECT built_in FROM roles WHERE id = ?1")
                .bind(role_id.to_string())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| ApiError::not_found("role does not exist"))?;
            if built_in != 0 {
                return Err(ApiError::forbidden());
            }
            sqlx::query("DELETE FROM roles WHERE id = ?1")
                .bind(role_id.to_string())
                .execute(&mut *tx)
                .await?;
            ensure_admin_remains(&mut tx).await?;
            tx.commit().await?;
            Ok(AdminResponse::Ok)
        }
        Op::SetUserRoles { user_id, role_ids } => {
            let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
            let user_exists =
                sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)")
                    .bind(user_id.to_string())
                    .fetch_one(&mut *tx)
                    .await?;
            if user_exists == 0 {
                return Err(ApiError::not_found("user does not exist"));
            }
            sqlx::query("DELETE FROM user_roles WHERE user_id = ?1")
                .bind(user_id.to_string())
                .execute(&mut *tx)
                .await?;
            for role_id in role_ids.iter().collect::<std::collections::BTreeSet<_>>() {
                let inserted = sqlx::query("INSERT INTO user_roles(user_id, role_id) SELECT ?1, id FROM roles WHERE id = ?2")
                    .bind(user_id.to_string())
                    .bind(role_id.to_string())
                    .execute(&mut *tx)
                    .await?;
                if inserted.rows_affected() != 1 {
                    return Err(ApiError::not_found("role does not exist"));
                }
            }
            ensure_admin_remains(&mut tx).await?;
            let roles = list_user_roles_tx(&mut tx, user_id).await?;
            tx.commit().await?;
            Ok(AdminResponse::UserRoles(roles))
        }
        Op::ListUserRoles { user_id } => Ok(AdminResponse::UserRoles(
            list_user_roles(state, user_id).await?,
        )),
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
            .execute(&state.inner.db.pool)
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
                .execute(&state.inner.db.pool)
                .await?;
            Ok(AdminResponse::Ok)
        }
        Op::ListRoleGrants { role_id } => Ok(AdminResponse::Grants(
            list_role_grants(state, role_id).await?,
        )),
        Op::ListTargets => Ok(AdminResponse::Targets(list_targets(state).await?)),
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
            .execute(&state.inner.db.pool)
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
                .execute(&state.inner.db.pool)
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
                .execute(&state.inner.db.pool)
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
                .execute(&state.inner.db.pool)
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
            .execute(&state.inner.db.pool)
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
