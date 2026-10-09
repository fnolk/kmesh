//! Group changes and access explanations use one database snapshot.
use std::collections::BTreeSet;

use super::*;
use crate::protocol::{AccessExplanation, AdminResponse, GroupChange, GroupChangeMode};

type Tx<'a> = sqlx::Transaction<'a, sqlx::Sqlite>;

async fn membership(tx: &mut Tx<'_>, user_id: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT group_id FROM user_access_groups WHERE user_id = ?1 ORDER BY group_id",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?)
}

async fn enabled_user(tx: &mut Tx<'_>, user_id: &str) -> Result<bool, ApiError> {
    sqlx::query_scalar::<_, bool>("SELECT enabled FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| ApiError::not_found("The user does not exist."))
}

async fn targets_for(
    tx: &mut Tx<'_>,
    groups: &[String],
    enabled: bool,
) -> Result<BTreeSet<String>, ApiError> {
    if !enabled {
        return Ok(BTreeSet::new());
    }
    let rows = sqlx::query("SELECT p.group_id, p.target_id FROM group_target_permissions p JOIN targets t ON t.id = p.target_id WHERE p.permission = 'ssh_connect' AND t.enabled = 1 AND t.deleted_at IS NULL")
        .fetch_all(&mut **tx).await?;
    let groups: BTreeSet<_> = groups.iter().collect();
    let mut targets = BTreeSet::new();
    for row in rows {
        if groups.contains(&row.try_get::<String, _>("group_id")?) {
            targets.insert(row.try_get("target_id")?);
        }
    }
    Ok(targets)
}

pub(super) async fn change_groups(
    state: &ServerState,
    actor: String,
    user_id: &str,
    groups: &[String],
    mode: GroupChangeMode,
    dry_run: bool,
    expected: Option<&GroupChange>,
) -> Result<AdminResponse, ApiError> {
    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    ensure_actor_is_admin(&mut tx, &actor).await?;
    let enabled = enabled_user(&mut tx, user_id).await?;
    let before = membership(&mut tx, user_id).await?;
    for group in groups {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM access_groups WHERE id = ?1)")
                .bind(group)
                .fetch_one(&mut *tx)
                .await?;
        if !exists {
            return Err(ApiError::not_found("The access group does not exist."));
        }
    }
    let old: BTreeSet<_> = before.iter().cloned().collect();
    let requested: BTreeSet<_> = groups.iter().cloned().collect();
    let after: Vec<_> = match mode {
        GroupChangeMode::Replace => requested,
        GroupChangeMode::Add => old.union(&requested).cloned().collect(),
        GroupChangeMode::Remove => old.difference(&requested).cloned().collect(),
    }
    .into_iter()
    .collect();
    let previous_targets = targets_for(&mut tx, &before, enabled).await?;
    let next_targets = targets_for(&mut tx, &after, enabled).await?;
    let change = GroupChange {
        user_id: user_id.to_owned(),
        before,
        after,
        lost_target_ids: previous_targets
            .difference(&next_targets)
            .cloned()
            .collect(),
        gained_target_ids: next_targets
            .difference(&previous_targets)
            .cloned()
            .collect(),
    };
    if expected.is_some_and(|expected| expected != &change) {
        return Err(ApiError::conflict(
            "Access changed after the preview. Run the command again.",
        ));
    }
    if !dry_run {
        sqlx::query("DELETE FROM user_access_groups WHERE user_id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for group in &change.after {
            sqlx::query("INSERT INTO user_access_groups(user_id, group_id) VALUES (?1, ?2)")
                .bind(user_id)
                .bind(group)
                .execute(&mut *tx)
                .await?;
        }
        insert_audit_event(
            &mut tx,
            AuditEvent {
                id: Uuid::new_v4(),
                occurred_at: unix_time(),
                actor_user_id: actor,
                operation: "change_user_access_groups",
                object_type: "user",
                object_id: Some(user_id.to_owned()),
                context: serde_json::json!({"mode": mode, "change": change}),
            },
        )
        .await?;
    }
    let access_groups = list_user_access_groups_tx(&mut tx, user_id).await?;
    tx.commit().await?;
    Ok(AdminResponse::GroupChange {
        change,
        applied: !dry_run,
        access_groups,
    })
}

pub(super) async fn explain(
    state: &ServerState,
    user_id: &str,
    target_id: &str,
) -> Result<AccessExplanation, ApiError> {
    let mut tx = state.inner.db.pool.begin().await?;
    let enabled = enabled_user(&mut tx, user_id).await?;
    let target: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM targets WHERE id = ?1 AND deleted_at IS NULL")
            .bind(target_id)
            .fetch_optional(&mut *tx)
            .await?;
    let access_groups = membership(&mut tx, user_id).await?;
    let granting_groups: Vec<String> = sqlx::query_scalar("SELECT p.group_id FROM group_target_permissions p JOIN user_access_groups u ON u.group_id = p.group_id WHERE u.user_id = ?1 AND p.target_id = ?2 AND p.permission = 'ssh_connect' ORDER BY p.group_id")
        .bind(user_id).bind(target_id).fetch_all(&mut *tx).await?;
    let mut blockers = Vec::new();
    if !enabled {
        blockers.push("user_disabled".to_owned());
    }
    match target {
        None => blockers.push("target_unavailable".to_owned()),
        Some(false) => blockers.push("target_disabled".to_owned()),
        Some(true) => {}
    }
    if access_groups.is_empty() {
        blockers.push("no_access_groups".to_owned());
    }
    if granting_groups.is_empty() {
        blockers.push("no_ssh_connect_grant".to_owned());
    }
    tx.commit().await?;
    Ok(AccessExplanation {
        user_id: user_id.to_owned(),
        target_id: target_id.to_owned(),
        access_groups,
        granting_groups,
        authorized: blockers.is_empty(),
        blockers,
        online: state
            .inner
            .online_agents
            .read()
            .await
            .contains_key(target_id),
    })
}
