//! Joined, read-only administration views built from the existing admin API.
//!
//! Keep credential-bearing protocol responses out of the serializable view model.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use ssh_key::{HashAlg, PublicKey};
use uuid::Uuid;

use crate::protocol::{
    AccessGroupView, AdminOperation, AdminRequest, AdminResponse, ApiTokenView, SystemRole,
    TargetPermission, TargetView, UserKeyView, UserView,
};

use super::{ClientContext, auth, output};

const CONSISTENCY: &str = "sequential API reads";

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub(super) enum Selection {
    Overview,
    User(String),
    AccessGroup(String),
    Target(String),
}

#[derive(Default)]
struct Snapshot {
    users: BTreeMap<String, UserView>,
    access_groups: BTreeMap<String, AccessGroupView>,
    targets: BTreeMap<String, TargetView>,
    memberships: BTreeMap<String, BTreeSet<String>>,
    grants: BTreeMap<String, BTreeSet<String>>,
    tokens: BTreeMap<String, Vec<ApiTokenView>>,
    keys: BTreeMap<String, Vec<UserKeyView>>,
}

#[derive(Serialize)]
struct JoinedView {
    selection: Selection,
    consistency: &'static str,
    collected_at_unix_secs: i64,
    warnings: Vec<String>,
    users: Vec<JoinedUser>,
    access_groups: Vec<JoinedAccessGroup>,
    targets: Vec<JoinedTarget>,
    access_paths: Vec<AccessPath>,
    tokens: Vec<TokenMetadata>,
    keys: Vec<KeyFingerprint>,
}

#[derive(Serialize)]
struct JoinedUser {
    user_id: String,
    username: String,
    enabled: bool,
    system_role: SystemRole,
    access_groups: Vec<String>,
    configured_target_ids: Vec<String>,
    authorized_target_ids: Vec<String>,
    active_token_count: usize,
    total_token_count: usize,
    key_count: usize,
}

#[derive(Serialize)]
struct JoinedAccessGroup {
    group_id: String,
    name: String,
    user_ids: Vec<String>,
    target_ids: Vec<String>,
}

#[derive(Serialize)]
struct JoinedTarget {
    target_id: String,
    name: String,
    available_in_target_list: bool,
    enabled: Option<bool>,
    online: Option<bool>,
    access_groups: Vec<String>,
    user_ids: Vec<String>,
    authorized_user_ids: Vec<String>,
}

#[derive(Serialize)]
struct AccessPath {
    user_id: String,
    target_id: String,
    access_groups: Vec<String>,
    permission: TargetPermission,
    authorized: bool,
    blockers: Vec<&'static str>,
    online: Option<bool>,
}

#[derive(Serialize)]
struct TokenMetadata {
    token_id: Uuid,
    user_id: String,
    label: String,
    status: &'static str,
    created_at: i64,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
}

#[derive(Serialize)]
struct KeyFingerprint {
    key_id: Uuid,
    user_id: String,
    label: String,
    fingerprint: String,
}

struct Scope {
    users: BTreeSet<String>,
    access_groups: BTreeSet<String>,
    targets: BTreeSet<String>,
}

pub(super) async fn run(context: &ClientContext, selection: Selection, json: bool) -> Result<()> {
    let token = auth::valid_access_token(context).await?;
    let (snapshot, selection) = Snapshot::load(context, &token, selection).await?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock precedes the Unix epoch")?
            .as_secs(),
    )
    .context("system clock exceeds the supported Unix timestamp range")?;
    // Do not emit any rows until every API read and join has succeeded.
    let view = snapshot.join(selection, now)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else {
        print_view(&view);
    }
    Ok(())
}

async fn request(
    context: &ClientContext,
    token: &str,
    operation: AdminOperation,
    description: &str,
) -> Result<AdminResponse> {
    context
        .api
        .admin(token, &AdminRequest { operation })
        .await
        .map_err(|error| anyhow::anyhow!("load admin view ({description}): {error:#}"))
}

fn unexpected_response(description: &str) -> anyhow::Error {
    // Never debug-print unexpected responses: they could contain issued credentials.
    anyhow::anyhow!("unexpected API response while loading admin view ({description})")
}

impl Snapshot {
    async fn load(
        context: &ClientContext,
        token: &str,
        selection: Selection,
    ) -> Result<(Self, Selection)> {
        let mut snapshot = Self::default();
        let AdminResponse::Users(users) =
            request(context, token, AdminOperation::ListUsers, "users").await?
        else {
            return Err(unexpected_response("users"));
        };
        snapshot.users = users.into_iter().map(|u| (u.user_id.clone(), u)).collect();
        let AdminResponse::AccessGroups(access_groups) =
            request(context, token, AdminOperation::ListGroups, "access groups").await?
        else {
            return Err(unexpected_response("access groups"));
        };
        snapshot.access_groups = access_groups
            .into_iter()
            .map(|r| (r.group_id.clone(), r))
            .collect();
        let AdminResponse::Targets(targets) =
            request(context, token, AdminOperation::ListTargets, "targets").await?
        else {
            return Err(unexpected_response("targets"));
        };
        snapshot.targets = targets
            .into_iter()
            .map(|t| (t.target_id.clone(), t))
            .collect();
        let selection = snapshot.resolve(selection)?;

        // A single in-flight request bounds server load regardless of directory size.
        for user_id in snapshot.users.keys() {
            let description = format!("access groups for user {}", output::cell(user_id));
            let AdminResponse::UserAccessGroups(access_groups) = request(
                context,
                token,
                AdminOperation::ListUserAccessGroups {
                    user_id: user_id.clone(),
                },
                &description,
            )
            .await?
            else {
                return Err(unexpected_response(&description));
            };
            snapshot.memberships.insert(
                user_id.clone(),
                access_groups
                    .into_iter()
                    .map(|access_group| access_group.group_id)
                    .collect(),
            );
        }
        for group_id in snapshot.access_groups.keys() {
            let description = format!("grants for access group {}", output::cell(group_id));
            let AdminResponse::Grants(grants) = request(
                context,
                token,
                AdminOperation::ListGroupGrants {
                    group_id: group_id.clone(),
                },
                &description,
            )
            .await?
            else {
                return Err(unexpected_response(&description));
            };
            let mut target_ids = BTreeSet::new();
            for grant in grants {
                ensure!(
                    grant.group_id == *group_id,
                    "Access group grant data changed. Run the view again."
                );
                match grant.permission {
                    TargetPermission::SshConnect => {
                        target_ids.insert(grant.target_id);
                    }
                }
            }
            snapshot.grants.insert(group_id.clone(), target_ids);
        }
        snapshot.validate_relationships()?;
        let scope = snapshot.scope(&selection);
        // Only fetch credential metadata for users relevant to the requested view.
        for user_id in &scope.users {
            let description = format!("token metadata for user {}", output::cell(user_id));
            let AdminResponse::ApiTokens(mut tokens) = request(
                context,
                token,
                AdminOperation::ListApiTokens {
                    user_id: user_id.clone(),
                },
                &description,
            )
            .await?
            else {
                return Err(unexpected_response(&description));
            };
            ensure!(
                tokens.iter().all(|t| t.user_id == *user_id),
                "inconsistent token ownership; retry the view"
            );
            tokens.sort_by_key(|t| t.token_id);
            tokens.dedup_by_key(|t| t.token_id);
            snapshot.tokens.insert(user_id.clone(), tokens);

            let description = format!("public key metadata for user {}", output::cell(user_id));
            let AdminResponse::Keys(mut keys) = request(
                context,
                token,
                AdminOperation::ListKeys {
                    user_id: user_id.clone(),
                },
                &description,
            )
            .await?
            else {
                return Err(unexpected_response(&description));
            };
            ensure!(
                keys.iter().all(|k| k.user_id == *user_id),
                "inconsistent public key ownership; retry the view"
            );
            keys.sort_by_key(|k| k.key_id);
            keys.dedup_by_key(|k| k.key_id);
            snapshot.keys.insert(user_id.clone(), keys);
        }
        Ok((snapshot, selection))
    }

    fn resolve(&self, selection: Selection) -> Result<Selection> {
        let (kind, supplied, exists) = match &selection {
            Selection::Overview => return Ok(selection),
            Selection::User(id) => (
                "user",
                id,
                self.users
                    .contains_key(id.trim().to_ascii_lowercase().as_str()),
            ),
            Selection::AccessGroup(id) => (
                "access group",
                id,
                self.access_groups
                    .contains_key(id.trim().to_ascii_lowercase().as_str()),
            ),
            Selection::Target(id) => (
                "target",
                id,
                self.targets
                    .contains_key(id.trim().to_ascii_lowercase().as_str()),
            ),
        };
        if !exists && matches!(selection, Selection::Target(_)) {
            anyhow::bail!(
                "Target ID {} is absent from the target list. Use the admin overview to view retained grants.",
                output::cell(supplied)
            );
        }
        ensure!(
            exists,
            "Unknown {kind} ID: {}. Use an exact ID from the admin overview.",
            output::cell(supplied)
        );
        let id = supplied.trim().to_ascii_lowercase();
        Ok(match selection {
            Selection::Overview => Selection::Overview,
            Selection::User(_) => Selection::User(id),
            Selection::AccessGroup(_) => Selection::AccessGroup(id),
            Selection::Target(_) => Selection::Target(id),
        })
    }

    fn validate_relationships(&self) -> Result<()> {
        ensure!(
            self.users
                .keys()
                .all(|id| self.memberships.contains_key(id)),
            "User access group data is missing. Use the view again."
        );
        ensure!(
            self.access_groups
                .keys()
                .all(|id| self.grants.contains_key(id)),
            "Access group grant data is missing. Use the view again."
        );
        for (user_id, access_groups) in &self.memberships {
            ensure!(
                self.users.contains_key(user_id),
                "The user list changed during the read. Use the view again."
            );
            ensure!(
                access_groups
                    .iter()
                    .all(|id| self.access_groups.contains_key(id)),
                "The user list changed during the read. Use the view again."
            );
        }
        for group_id in self.grants.keys() {
            ensure!(
                self.access_groups.contains_key(group_id),
                "Access group grants changed during the read. Use the view again."
            );
            // Target deletion is soft: ListGroupGrants can retain a target ID that
            // ListTargets omits. Preserve that reference as unavailable below.
        }
        Ok(())
    }

    fn user_access_groups(&self, user_id: &str) -> BTreeSet<String> {
        self.memberships.get(user_id).cloned().unwrap_or_default()
    }

    fn access_group_targets(&self, group_id: &str) -> BTreeSet<String> {
        self.grants.get(group_id).cloned().unwrap_or_default()
    }

    fn access_group_users(&self, group_id: &str) -> BTreeSet<String> {
        self.memberships
            .iter()
            .filter(|(_, access_groups)| access_groups.contains(group_id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn target_access_groups(&self, target_id: &str) -> BTreeSet<String> {
        self.grants
            .iter()
            .filter(|(_, targets)| targets.contains(target_id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn targets_for_access_groups(&self, access_groups: &BTreeSet<String>) -> BTreeSet<String> {
        access_groups
            .iter()
            .flat_map(|id| self.access_group_targets(id))
            .collect()
    }

    fn users_for_access_groups(&self, access_groups: &BTreeSet<String>) -> BTreeSet<String> {
        access_groups
            .iter()
            .flat_map(|id| self.access_group_users(id))
            .collect()
    }

    fn scope(&self, selection: &Selection) -> Scope {
        match selection {
            Selection::Overview => Scope {
                users: self.users.keys().cloned().collect(),
                access_groups: self.access_groups.keys().cloned().collect(),
                targets: self
                    .targets
                    .keys()
                    .chain(self.grants.values().flatten())
                    .cloned()
                    .collect(),
            },
            Selection::User(id) => {
                let access_groups = self.user_access_groups(id);
                Scope {
                    users: BTreeSet::from([id.clone()]),
                    targets: self.targets_for_access_groups(&access_groups),
                    access_groups,
                }
            }
            Selection::AccessGroup(id) => Scope {
                users: self.access_group_users(id),
                access_groups: BTreeSet::from([id.clone()]),
                targets: self.access_group_targets(id),
            },
            Selection::Target(id) => {
                let access_groups = self.target_access_groups(id);
                Scope {
                    users: self.users_for_access_groups(&access_groups),
                    access_groups,
                    targets: BTreeSet::from([id.clone()]),
                }
            }
        }
    }

    fn join(&self, selection: Selection, now: i64) -> Result<JoinedView> {
        let selection = self.resolve(selection)?;
        self.validate_relationships()?;
        let scope = self.scope(&selection);
        let mut users = Vec::new();
        let mut tokens = Vec::new();
        let mut keys = Vec::new();
        for id in &scope.users {
            let user = &self.users[id];
            let group_ids = self.user_access_groups(id);
            let configured = self.targets_for_access_groups(&group_ids);
            let authorized = configured
                .iter()
                .filter(|id| {
                    user.enabled && self.targets.get(*id).is_some_and(|target| target.enabled)
                })
                .cloned()
                .collect();
            let user_tokens = self
                .tokens
                .get(id)
                .context("missing token metadata; retry the view")?;
            let user_keys = self
                .keys
                .get(id)
                .context("missing public key metadata; retry the view")?;
            users.push(JoinedUser {
                user_id: id.clone(),
                username: user.username.clone(),
                enabled: user.enabled,
                system_role: user.system_role,
                access_groups: group_ids.into_iter().collect(),
                configured_target_ids: configured.into_iter().collect(),
                authorized_target_ids: authorized,
                active_token_count: user_tokens
                    .iter()
                    .filter(|t| token_status(t, now) == "active")
                    .count(),
                total_token_count: user_tokens.len(),
                key_count: user_keys.len(),
            });
            tokens.extend(user_tokens.iter().map(|token| TokenMetadata {
                token_id: token.token_id,
                user_id: token.user_id.clone(),
                label: token.label.clone(),
                status: token_status(token, now),
                created_at: token.created_at,
                expires_at: token.expires_at,
                revoked_at: token.revoked_at,
            }));
            for key in user_keys {
                let public_key = PublicKey::from_openssh(&key.public_key).map_err(|_| {
                    anyhow::anyhow!("invalid public key metadata for key {}", key.key_id)
                })?;
                keys.push(KeyFingerprint {
                    key_id: key.key_id,
                    user_id: key.user_id.clone(),
                    label: key.label.clone(),
                    fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
                });
            }
        }
        tokens.sort_by(|a, b| (&a.user_id, a.token_id).cmp(&(&b.user_id, b.token_id)));
        keys.sort_by(|a, b| (&a.user_id, a.key_id).cmp(&(&b.user_id, b.key_id)));
        let access_groups = scope
            .access_groups
            .iter()
            .map(|id| JoinedAccessGroup {
                group_id: id.clone(),
                name: self.access_groups[id].name.clone(),
                user_ids: self.access_group_users(id).into_iter().collect(),
                target_ids: self.access_group_targets(id).into_iter().collect(),
            })
            .collect();
        let targets = scope
            .targets
            .iter()
            .map(|id| {
                let target = self.targets.get(id);
                let group_ids = self.target_access_groups(id);
                let user_ids = self.users_for_access_groups(&group_ids);
                JoinedTarget {
                    target_id: id.clone(),
                    name: target.map_or_else(|| "-".to_owned(), |target| target.name.clone()),
                    available_in_target_list: target.is_some(),
                    enabled: target.map(|target| target.enabled),
                    online: target.map(|target| target.online),
                    authorized_user_ids: user_ids
                        .iter()
                        .filter(|user| {
                            target.is_some_and(|target| target.enabled) && self.users[*user].enabled
                        })
                        .cloned()
                        .collect(),
                    access_groups: group_ids.into_iter().collect(),
                    user_ids: user_ids.into_iter().collect(),
                }
            })
            .collect();

        let mut access_paths = Vec::new();
        for user_id in &scope.users {
            let user = &self.users[user_id];
            let user_access_groups = self.user_access_groups(user_id);
            let mut paths: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for group_id in user_access_groups.intersection(&scope.access_groups) {
                for target_id in self
                    .access_group_targets(group_id)
                    .intersection(&scope.targets)
                {
                    paths
                        .entry(target_id.clone())
                        .or_default()
                        .insert(group_id.clone());
                }
            }
            for (target_id, group_ids) in paths {
                let target = self.targets.get(&target_id);
                let mut blockers = Vec::new();
                if !user.enabled {
                    blockers.push("user_disabled");
                }
                match target {
                    Some(target) if !target.enabled => blockers.push("target_disabled"),
                    None => blockers.push("target_unavailable"),
                    _ => {}
                }
                access_paths.push(AccessPath {
                    user_id: user_id.clone(),
                    target_id,
                    access_groups: group_ids.into_iter().collect(),
                    permission: TargetPermission::SshConnect,
                    authorized: blockers.is_empty(),
                    blockers,
                    online: target.map(|target| target.online),
                });
            }
        }
        Ok(JoinedView {
            warnings: scope.targets.iter()
                .filter(|id| !self.targets.contains_key(*id))
                .map(|id| format!("Target {id} is absent from the target listing (removed or changed during reads); retained grants are shown, but access is unavailable."))
                .collect(),
            selection,
            consistency: CONSISTENCY,
            collected_at_unix_secs: now,
            users,
            access_groups,
            targets,
            access_paths,
            tokens,
            keys,
        })
    }
}

fn token_status(token: &ApiTokenView, now: i64) -> &'static str {
    if token.revoked_at.is_some() {
        "revoked"
    } else if token.expires_at.is_some_and(|expires| expires <= now) {
        "expired"
    } else {
        "active"
    }
}

fn list(ids: &[String]) -> String {
    if ids.is_empty() {
        "-".to_owned()
    } else {
        ids.join(", ")
    }
}

fn online(value: bool) -> &'static str {
    if value { "online" } else { "offline" }
}

fn target_state(value: Option<bool>) -> &'static str {
    value.map_or("unavailable", output::state)
}

fn availability(value: Option<bool>) -> &'static str {
    value.map_or("unknown", online)
}

fn timestamp(value: Option<i64>, absent: &str) -> String {
    value.map_or_else(|| absent.to_owned(), |value| value.to_string())
}

struct Table {
    title: &'static str,
    headers: &'static [&'static str],
    rows: Vec<Vec<String>>,
}

fn tables(view: &JoinedView) -> Vec<Table> {
    if matches!(view.selection, Selection::AccessGroup(_)) {
        let show_user_names = view.users.iter().any(|user| user.user_id != user.username);
        let show_target_names = view
            .targets
            .iter()
            .any(|target| target.available_in_target_list && target.target_id != target.name);
        return vec![
            Table {
                title: "Members",
                headers: if show_user_names {
                    &["USER ID", "STATE", "NAME"]
                } else {
                    &["USER ID", "STATE"]
                },
                rows: view
                    .users
                    .iter()
                    .map(|user| {
                        let mut row =
                            vec![user.user_id.clone(), output::state(user.enabled).to_owned()];
                        if show_user_names {
                            row.push(user.username.clone());
                        }
                        row
                    })
                    .collect(),
            },
            Table {
                title: "Targets",
                headers: if show_target_names {
                    &["TARGET ID", "STATE", "AVAILABILITY", "NAME"]
                } else {
                    &["TARGET ID", "STATE", "AVAILABILITY"]
                },
                rows: view
                    .targets
                    .iter()
                    .map(|target| {
                        let mut row = vec![
                            target.target_id.clone(),
                            target_state(target.enabled).to_owned(),
                            availability(target.online).to_owned(),
                        ];
                        if show_target_names {
                            row.push(if target.available_in_target_list {
                                target.name.clone()
                            } else {
                                "-".to_owned()
                            });
                        }
                        row
                    })
                    .collect(),
            },
        ];
    }

    let mut tables = vec![
        Table {
            title: "Users",
            headers: &[
                "USER ID",
                "NAME",
                "STATE",
                "PLATFORM ROLE",
                "GROUP IDS",
                "AUTHORIZED SSH TARGETS",
                "TOKENS A/T",
                "REGISTERED KEYS",
            ],
            rows: view
                .users
                .iter()
                .map(|user| {
                    vec![
                        user.user_id.clone(),
                        user.username.clone(),
                        output::state(user.enabled).to_owned(),
                        user.system_role.as_str().to_owned(),
                        list(&user.access_groups),
                        list(&user.authorized_target_ids),
                        format!("{}/{}", user.active_token_count, user.total_token_count),
                        user.key_count.to_string(),
                    ]
                })
                .collect(),
        },
        Table {
            title: "Access groups",
            headers: &["GROUP ID", "NAME", "USERS", "SSH TARGETS"],
            rows: view
                .access_groups
                .iter()
                .map(|access_group| {
                    vec![
                        access_group.group_id.clone(),
                        access_group.name.clone(),
                        list(&access_group.user_ids),
                        list(&access_group.target_ids),
                    ]
                })
                .collect(),
        },
        Table {
            title: "Targets",
            headers: &[
                "TARGET ID",
                "NAME",
                "STATE",
                "AVAILABILITY",
                "GROUP IDS",
                "ASSIGNED USERS",
                "AUTHORIZED USERS",
            ],
            rows: view
                .targets
                .iter()
                .map(|target| {
                    vec![
                        target.target_id.clone(),
                        target.name.clone(),
                        target_state(target.enabled).to_owned(),
                        availability(target.online).to_owned(),
                        list(&target.access_groups),
                        list(&target.user_ids),
                        list(&target.authorized_user_ids),
                    ]
                })
                .collect(),
        },
    ];
    if !matches!(view.selection, Selection::Overview) {
        tables.extend([
            Table {
                title: "SSH access paths for this selection",
                headers: &[
                    "USER ID",
                    "TARGET ID",
                    "VIA GROUP IDS",
                    "PERMISSION",
                    "AUTHORIZATION",
                    "AVAILABILITY",
                ],
                rows: view
                    .access_paths
                    .iter()
                    .map(|path| {
                        vec![
                            path.user_id.clone(),
                            path.target_id.clone(),
                            list(&path.access_groups),
                            "ssh_connect".to_owned(),
                            if path.authorized {
                                "allowed".to_owned()
                            } else {
                                path.blockers.join(", ")
                            },
                            availability(path.online).to_owned(),
                        ]
                    })
                    .collect(),
            },
            Table {
                title: "Related users' API token metadata (Unix seconds)",
                headers: &[
                    "TOKEN ID", "USER ID", "LABEL", "STATUS", "CREATED", "EXPIRES", "REVOKED",
                ],
                rows: view
                    .tokens
                    .iter()
                    .map(|token| {
                        vec![
                            token.token_id.to_string(),
                            token.user_id.clone(),
                            token.label.clone(),
                            token.status.to_owned(),
                            token.created_at.to_string(),
                            timestamp(token.expires_at, "never"),
                            timestamp(token.revoked_at, "-"),
                        ]
                    })
                    .collect(),
            },
            Table {
                title: "Related users' SSH public key fingerprints",
                headers: &["KEY ID", "USER ID", "LABEL", "SHA256 FINGERPRINT"],
                rows: view
                    .keys
                    .iter()
                    .map(|key| {
                        vec![
                            key.key_id.to_string(),
                            key.user_id.clone(),
                            key.label.clone(),
                            key.fingerprint.clone(),
                        ]
                    })
                    .collect(),
            },
        ]);
    }
    tables
}

fn print_view(view: &JoinedView) {
    match &view.selection {
        Selection::Overview => println!("Admin overview"),
        Selection::User(id) => println!("User: {}", output::cell(id)),
        Selection::AccessGroup(id) => {
            println!("Access group: {}", output::cell(id));
            let group = &view.access_groups[0];
            if group.name != group.group_id {
                println!("Name: {}", output::cell(&group.name));
            }
            println!("SSH permission: ssh_connect");
            println!();
        }
        Selection::Target(id) => println!("Target: {}", output::cell(id)),
    }
    if !matches!(view.selection, Selection::AccessGroup(_)) {
        println!(
            "Read consistency: {}. Collected at {} (Unix seconds).",
            view.consistency, view.collected_at_unix_secs
        );
    }
    for warning in &view.warnings {
        println!("Warning: {}", output::cell(warning));
    }
    for (index, table) in tables(view).into_iter().enumerate() {
        if index > 0 && matches!(view.selection, Selection::AccessGroup(_)) {
            println!();
        }
        output::print_table(table.title, table.headers, table.rows);
    }
    if !matches!(view.selection, Selection::AccessGroup(_)) {
        println!(
            "SSH access path: user -> access group -> ssh_connect grant -> target. Disabled users or targets block authorization. Online status reports availability."
        );
        println!(
            "Platform roles control administration. Access groups control SSH access. Access paths are limited to this selection."
        );
        println!(
            "Tokens A/T = active/total by expiry and revocation. Disabled users cannot authenticate. Tokens and keys belong to users, not individual targets."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 test-vector public key, encoded as an OpenSSH public key.
    const PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

    fn fixture() -> Snapshot {
        let mut snapshot = Snapshot::default();
        for (id, enabled) in [("alice", true), ("bob", false), ("root", true)] {
            snapshot.users.insert(
                id.to_owned(),
                UserView {
                    user_id: id.to_owned(),
                    username: id.to_owned(),
                    system_role: if id == "root" {
                        SystemRole::Admin
                    } else {
                        SystemRole::Member
                    },
                    enabled,
                },
            );
            snapshot.tokens.insert(id.to_owned(), vec![]);
            snapshot.keys.insert(id.to_owned(), vec![]);
        }
        for id in ["admin", "dev", "ops"] {
            snapshot.access_groups.insert(
                id.to_owned(),
                AccessGroupView {
                    group_id: id.to_owned(),
                    name: id.to_owned(),
                },
            );
        }
        for (id, enabled, online) in [("build", true, false), ("prod", false, true)] {
            snapshot.targets.insert(
                id.to_owned(),
                TargetView {
                    target_id: id.to_owned(),
                    name: id.to_owned(),
                    enabled,
                    online,
                },
            );
        }
        snapshot.memberships.insert(
            "alice".to_owned(),
            BTreeSet::from(["dev".to_owned(), "ops".to_owned()]),
        );
        snapshot
            .memberships
            .insert("bob".to_owned(), BTreeSet::from(["ops".to_owned()]));
        snapshot
            .memberships
            .insert("root".to_owned(), BTreeSet::from(["admin".to_owned()]));
        snapshot
            .grants
            .insert("dev".to_owned(), BTreeSet::from(["build".to_owned()]));
        snapshot.grants.insert(
            "ops".to_owned(),
            BTreeSet::from(["build".to_owned(), "prod".to_owned()]),
        );
        snapshot.grants.insert("admin".to_owned(), BTreeSet::new());
        snapshot
    }

    fn token(id: u128, expires_at: Option<i64>, revoked_at: Option<i64>) -> ApiTokenView {
        ApiTokenView {
            token_id: Uuid::from_u128(id),
            user_id: "alice".to_owned(),
            label: "test".to_owned(),
            created_at: 1,
            expires_at,
            revoked_at,
        }
    }

    #[test]
    fn joins_deduplicate_paths_and_do_not_grant_admin_implicit_ssh_access() {
        let view = fixture().join(Selection::Overview, 100).unwrap();
        let alice = &view.users[0];
        assert_eq!(alice.user_id, "alice");
        assert_eq!(alice.configured_target_ids, ["build", "prod"]);
        assert_eq!(alice.authorized_target_ids, ["build"]);
        assert!(view.users[1].authorized_target_ids.is_empty());
        assert!(view.users[2].authorized_target_ids.is_empty());
        assert_eq!(view.access_paths.len(), 4);
        let path = &view.access_paths[0];
        assert_eq!(path.access_groups, ["dev", "ops"]);
        assert!(path.authorized, "offline does not remove authorization");
        assert_eq!(path.online, Some(false));
        assert_eq!(view.access_paths[1].blockers, ["target_disabled"]);
        assert_eq!(
            view.access_paths[3].blockers,
            ["user_disabled", "target_disabled"]
        );
        assert_eq!(view.targets[0].user_ids, ["alice", "bob"]);
        assert_eq!(view.targets[0].authorized_user_ids, ["alice"]);
    }

    #[test]
    fn detail_views_resolve_normalized_exact_ids_and_related_entities() {
        let snapshot = fixture();
        let user = snapshot
            .join(Selection::User(" ALICE ".to_owned()), 100)
            .unwrap();
        assert_eq!(user.users.len(), 1);
        assert_eq!(user.access_groups.len(), 2);
        assert_eq!(user.targets.len(), 2);
        let access_group = snapshot
            .join(Selection::AccessGroup(" DeV ".to_owned()), 100)
            .unwrap();
        assert_eq!(access_group.users.len(), 1);
        assert_eq!(access_group.targets.len(), 1);
        assert_eq!(access_group.access_paths[0].access_groups, ["dev"]);
        let target = snapshot
            .join(Selection::Target(" BUILD ".to_owned()), 100)
            .unwrap();
        assert_eq!(target.users.len(), 2);
        assert_eq!(target.access_groups.len(), 2);
        assert_eq!(target.targets.len(), 1);
        for selection in [
            Selection::User("ali".to_owned()),
            Selection::AccessGroup("missing".to_owned()),
            Selection::Target("missing".to_owned()),
        ] {
            assert!(snapshot.join(selection, 100).is_err());
        }
    }

    #[test]
    fn expiry_boundary_and_revocation_are_reflected_in_counts_and_metadata() {
        let mut snapshot = fixture();
        snapshot.tokens.insert(
            "alice".to_owned(),
            vec![
                token(1, None, None),
                token(2, Some(101), None),
                token(3, Some(100), None),
                token(4, Some(99), None),
                token(5, Some(99), Some(50)),
                token(6, None, Some(60)),
            ],
        );
        let view = snapshot
            .join(Selection::User("alice".to_owned()), 100)
            .unwrap();
        assert_eq!(view.users[0].active_token_count, 2);
        assert_eq!(view.users[0].total_token_count, 6);
        assert_eq!(
            view.tokens.iter().map(|t| t.status).collect::<Vec<_>>(),
            [
                "active", "active", "expired", "expired", "revoked", "revoked"
            ]
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["tokens"][2]["expires_at"], 100);
        assert!(json["tokens"][0].get("token").is_none());
    }

    #[test]
    fn public_keys_are_fingerprinted_and_never_serialized_as_key_material() {
        let mut snapshot = fixture();
        snapshot.keys.insert(
            "alice".to_owned(),
            vec![UserKeyView {
                key_id: Uuid::from_u128(1),
                user_id: "alice".to_owned(),
                public_key: PUBLIC_KEY.to_owned(),
                label: "laptop".to_owned(),
            }],
        );
        let view = snapshot
            .join(Selection::User("alice".to_owned()), 100)
            .unwrap();
        assert_eq!(view.users[0].key_count, 1);
        assert!(view.keys[0].fingerprint.starts_with("SHA256:"));
        assert_eq!(
            view.keys[0].fingerprint,
            PublicKey::from_openssh(PUBLIC_KEY)
                .unwrap()
                .fingerprint(HashAlg::Sha256)
                .to_string()
        );
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("ssh-ed25519"));
        assert!(!json.contains("public_key"));
        assert!(!json.contains("private_key"));
    }

    #[test]
    fn human_tables_escape_untrusted_labels_and_names() {
        let mut snapshot = fixture();
        let malicious = "escape\x1b[2J\nforged\r\trow";
        snapshot.users.get_mut("alice").unwrap().username = malicious.to_owned();
        snapshot.access_groups.get_mut("dev").unwrap().name = malicious.to_owned();
        snapshot.targets.get_mut("build").unwrap().name = malicious.to_owned();
        let mut api_token = token(1, None, None);
        api_token.label = malicious.to_owned();
        snapshot.tokens.insert("alice".to_owned(), vec![api_token]);
        snapshot.keys.insert(
            "alice".to_owned(),
            vec![UserKeyView {
                key_id: Uuid::from_u128(1),
                user_id: "alice".to_owned(),
                public_key: PUBLIC_KEY.to_owned(),
                label: malicious.to_owned(),
            }],
        );
        let view = snapshot
            .join(Selection::User("alice".to_owned()), 100)
            .unwrap();
        for table in tables(&view) {
            let rendered = output::render_table(table.title, table.headers, table.rows);
            assert!(!rendered.contains('\x1b'));
            assert!(!rendered.contains('\r'));
            assert!(!rendered.contains('\t'));
            assert!(!rendered.contains("\nforged"));
        }
    }

    #[test]
    fn empty_overview_is_complete_and_inconsistent_reads_fail_closed() {
        let view = Snapshot::default().join(Selection::Overview, 100).unwrap();
        assert!(view.users.is_empty());
        assert!(view.access_groups.is_empty());
        assert!(view.targets.is_empty());
        assert!(view.access_paths.is_empty());
        assert_eq!(tables(&view).len(), 3);
        assert_eq!(view.consistency, CONSISTENCY);
        let mut snapshot = fixture();
        snapshot.access_groups.remove("dev");
        assert!(snapshot.join(Selection::Overview, 100).is_err());
        let mut snapshot = fixture();
        snapshot.users.remove("alice");
        assert!(snapshot.join(Selection::Overview, 100).is_err());
        let mut snapshot = fixture();
        snapshot.memberships.remove("alice");
        assert!(snapshot.join(Selection::Overview, 100).is_err());
        let mut snapshot = fixture();
        snapshot.grants.remove("dev");
        assert!(snapshot.join(Selection::Overview, 100).is_err());
        let mut snapshot = fixture();
        snapshot.tokens.remove("alice");
        assert!(snapshot.join(Selection::Overview, 100).is_err());
    }

    #[test]
    fn retained_grants_to_removed_targets_are_visible_but_never_authorized() {
        let mut snapshot = fixture();
        // DeleteTarget retains group_target_permissions, but ListTargets omits the row.
        snapshot.targets.remove("build");
        for selection in [
            Selection::Overview,
            Selection::User("alice".to_owned()),
            Selection::AccessGroup("dev".to_owned()),
        ] {
            let view = snapshot.join(selection, 100).unwrap();
            let target = view
                .targets
                .iter()
                .find(|target| target.target_id == "build")
                .unwrap();
            assert!(!target.available_in_target_list);
            assert_eq!(target.enabled, None);
            assert_eq!(target.online, None);
            assert!(target.authorized_user_ids.is_empty());
            assert!(
                view.warnings
                    .iter()
                    .any(|warning| warning.contains("build"))
            );
            assert!(
                view.users
                    .iter()
                    .all(|user| !user.authorized_target_ids.iter().any(|id| id == "build"))
            );
            for path in view
                .access_paths
                .iter()
                .filter(|path| path.target_id == "build")
            {
                assert!(!path.authorized);
                assert_eq!(path.online, None);
                assert!(path.blockers.contains(&"target_unavailable"));
            }
            let json = serde_json::to_value(&view).unwrap();
            assert!(json["targets"][0]["enabled"].is_null());
            let target_table = tables(&view)
                .into_iter()
                .find(|table| table.title == "Targets")
                .unwrap();
            let rendered =
                output::render_table(target_table.title, target_table.headers, target_table.rows);
            assert!(rendered.contains("unavailable"));
            assert!(rendered.contains("unknown"));
        }
        assert!(
            snapshot
                .join(Selection::Target("build".to_owned()), 100)
                .is_err()
        );
    }

    #[test]
    fn isolated_access_groups_and_targets_still_have_useful_empty_detail_views() {
        let mut snapshot = fixture();
        snapshot
            .memberships
            .insert("root".to_owned(), BTreeSet::new());
        let access_group = snapshot
            .join(Selection::AccessGroup("admin".to_owned()), 100)
            .unwrap();
        assert_eq!(access_group.access_groups.len(), 1);
        assert!(access_group.users.is_empty());
        assert!(access_group.targets.is_empty());
        assert!(access_group.tokens.is_empty());
        assert!(access_group.keys.is_empty());
        let group_tables = tables(&access_group);
        assert_eq!(
            group_tables
                .iter()
                .map(|table| table.title)
                .collect::<Vec<_>>(),
            ["Members", "Targets"]
        );
        assert!(group_tables[0].rows.is_empty());
        assert!(group_tables[1].rows.is_empty());
        for targets in snapshot.grants.values_mut() {
            targets.clear();
        }
        let target = snapshot
            .join(Selection::Target("build".to_owned()), 100)
            .unwrap();
        assert_eq!(target.targets.len(), 1);
        assert!(target.users.is_empty());
        assert!(target.access_groups.is_empty());
        assert!(target.access_paths.is_empty());
    }

    #[test]
    fn access_group_tables_show_only_members_and_targets_with_distinct_names() {
        let view = fixture()
            .join(Selection::AccessGroup("ops".to_owned()), 100)
            .unwrap();
        let group_tables = tables(&view);
        assert_eq!(group_tables[0].headers, ["USER ID", "STATE"]);
        assert_eq!(
            group_tables[1].headers,
            ["TARGET ID", "STATE", "AVAILABILITY"]
        );

        let mut snapshot = fixture();
        snapshot.users.get_mut("alice").unwrap().username = "Alice".to_owned();
        snapshot.targets.get_mut("build").unwrap().name = "Build server".to_owned();
        snapshot.access_groups.get_mut("ops").unwrap().name = "Operations".to_owned();

        let view = snapshot
            .join(Selection::AccessGroup("ops".to_owned()), 100)
            .unwrap();
        let group_tables = tables(&view);
        assert_eq!(group_tables.len(), 2);
        assert_eq!(group_tables[0].headers, ["USER ID", "STATE", "NAME"]);
        assert_eq!(
            group_tables[0].rows,
            [
                ["alice", "enabled", "Alice"].map(str::to_owned).to_vec(),
                ["bob", "disabled", "bob"].map(str::to_owned).to_vec(),
            ]
        );
        assert_eq!(
            group_tables[1].headers,
            ["TARGET ID", "STATE", "AVAILABILITY", "NAME"]
        );
        assert_eq!(
            group_tables[1].rows,
            [
                ["build", "enabled", "offline", "Build server"]
                    .map(str::to_owned)
                    .to_vec(),
                ["prod", "disabled", "online", "prod"]
                    .map(str::to_owned)
                    .to_vec(),
            ]
        );
        let rendered = group_tables
            .into_iter()
            .map(|table| output::render_table(table.title, table.headers, table.rows))
            .collect::<String>();
        assert!(!rendered.contains("GROUP ID"));
        assert!(!rendered.contains("GROUP IDS"));
        assert!(!rendered.contains("AUTHORIZED USERS"));
        assert!(!rendered.contains("ssh_connect"));
        assert_eq!(view.access_groups[0].name, "Operations");

        let mut snapshot = fixture();
        snapshot.targets.get_mut("build").unwrap().name = "Build server".to_owned();
        snapshot.targets.remove("prod");
        let view = snapshot
            .join(Selection::AccessGroup("ops".to_owned()), 100)
            .unwrap();
        let group_tables = tables(&view);
        let target_table = &group_tables[1];
        assert_eq!(
            target_table.rows[1],
            ["prod", "unavailable", "unknown", "-"]
                .map(str::to_owned)
                .to_vec()
        );
        assert!(view.warnings.iter().any(|warning| warning.contains("prod")));
    }

    #[test]
    fn malformed_key_metadata_fails_without_exposing_its_contents() {
        let mut snapshot = fixture();
        snapshot.keys.insert(
            "alice".to_owned(),
            vec![UserKeyView {
                key_id: Uuid::from_u128(1),
                user_id: "alice".to_owned(),
                public_key: "malformed-secret-material".to_owned(),
                label: "test".to_owned(),
            }],
        );
        let error = snapshot
            .join(Selection::User("alice".to_owned()), 100)
            .err()
            .expect("reject malformed key metadata");
        assert!(error.to_string().contains("invalid public key metadata"));
        assert!(!error.to_string().contains("malformed-secret-material"));
    }
}
