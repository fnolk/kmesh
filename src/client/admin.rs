use std::fs;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use rustyline::{
    Context as LineContext, Editor, Helper,
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    validate::{ValidationContext, ValidationResult, Validator},
};

use crate::protocol::{
    AdminOperation, AdminRequest, AdminResponse, ApiTokenView, RelayEndpointSide,
    RelaySessionPhase, RelayTrafficView, RoleGrantView, TargetView, UserKeyView, UserView,
};

use super::{
    ClientContext, auth,
    cli::{
        AdminArgs, AdminCommand, ApiTokenAction, GrantAction, KeyAction, RelayAction, RoleAction,
        TargetAction, UserAction,
    },
};

#[derive(Debug, Parser)]
#[command(
    name = "admin",
    about = "Manage users, SSH keys, roles, grants, targets, and relay traffic",
    disable_help_subcommand = true
)]
struct AdminLine {
    #[arg(long, help = "Output the response as JSON")]
    json: bool,
    #[command(subcommand)]
    command: Option<AdminCommand>,
}

pub async fn run(context: &ClientContext, args: &AdminArgs) -> Result<()> {
    if let Some(command) = &args.command {
        execute(context, command.clone(), args.json).await
    } else {
        repl(context).await
    }
}

async fn repl(context: &ClientContext) -> Result<()> {
    let mut editor = Editor::<AdminHelper, rustyline::history::DefaultHistory>::new()?;
    editor.set_helper(Some(AdminHelper));
    loop {
        match editor.readline("admin> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = editor.add_history_entry(line);
                if matches!(line, "exit" | "quit") {
                    return Ok(());
                }
                if matches!(line, "help" | "?") {
                    print_help();
                    continue;
                }
                let Some(words) = shlex::split(line) else {
                    eprintln!("命令引号不完整。");
                    continue;
                };
                let mut argv = vec!["admin".to_owned()];
                argv.extend(words);
                match AdminLine::try_parse_from(argv) {
                    Ok(parsed) => {
                        if let Some(command) = parsed.command
                            && let Err(error) = execute(context, command, parsed.json).await
                        {
                            eprintln!("{}", format_error(&error));
                        }
                    }
                    Err(error) => eprintln!("{}", error.render().to_string().trim()),
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => return Ok(()),
            Err(error) => return Err(error).context("read admin command"),
        }
    }
}

async fn execute(context: &ClientContext, command: AdminCommand, json: bool) -> Result<()> {
    let mut operation = match command {
        AdminCommand::Users { action } => match action {
            UserAction::List => AdminOperation::ListUsers,
            UserAction::Create { username } => AdminOperation::CreateUser { username },
            UserAction::Disable { user_id } => AdminOperation::SetUserEnabled {
                user_id,
                enabled: false,
            },
            UserAction::Enable { user_id } => AdminOperation::SetUserEnabled {
                user_id,
                enabled: true,
            },
            UserAction::Roles { user_id, role_ids } => {
                AdminOperation::SetUserRoles { user_id, role_ids }
            }
            UserAction::ShowRoles { user_id } => AdminOperation::ListUserRoles { user_id },
        },
        AdminCommand::Tokens { action } => match action {
            ApiTokenAction::Create {
                user_id,
                label,
                expires_in,
            } => AdminOperation::CreateApiToken {
                user_id,
                label,
                expires_in_secs: expires_in,
            },
            ApiTokenAction::List { user_id } => AdminOperation::ListApiTokens { user_id },
            ApiTokenAction::Revoke { token_id } => AdminOperation::RevokeApiToken { token_id },
        },
        AdminCommand::Keys { action } => match action {
            KeyAction::List { user_id } => AdminOperation::ListKeys { user_id },
            KeyAction::Add {
                user_id,
                public_key_file,
                label,
            } => AdminOperation::AddUserKey {
                user_id,
                public_key: fs::read_to_string(&public_key_file).with_context(|| {
                    format!("read SSH public key file {}", public_key_file.display())
                })?,
                label,
            },
            KeyAction::Remove { key_id } => AdminOperation::RemoveUserKey { key_id },
        },
        AdminCommand::Roles { action } => match action {
            RoleAction::List => AdminOperation::ListRoles,
            RoleAction::Create { name } => AdminOperation::CreateRole { name },
            RoleAction::Delete { role_id } => AdminOperation::DeleteRole { role_id },
        },
        AdminCommand::Grants { action } => match action {
            GrantAction::List { role_id } => AdminOperation::ListRoleGrants { role_id },
            GrantAction::Add {
                role_id,
                target_id,
                permission,
            } => AdminOperation::GrantTarget {
                role_id,
                target_id,
                permission: permission.into(),
            },
            GrantAction::Remove {
                role_id,
                target_id,
                permission,
            } => AdminOperation::RevokeTarget {
                role_id,
                target_id,
                permission: permission.into(),
            },
        },
        AdminCommand::Targets { action } => match action {
            TargetAction::List => AdminOperation::ListTargets,
            TargetAction::Create { name } => AdminOperation::CreateTarget { name },
            TargetAction::Rename { target_id, name } => {
                AdminOperation::RenameTarget { target_id, name }
            }
            TargetAction::Enable { target_id } => AdminOperation::SetTargetEnabled {
                target_id,
                enabled: true,
            },
            TargetAction::Disable { target_id } => AdminOperation::SetTargetEnabled {
                target_id,
                enabled: false,
            },
            TargetAction::Delete { target_id } => AdminOperation::DeleteTarget { target_id },
            TargetAction::IssueEnrollment { target_id } => {
                AdminOperation::IssueEnrollment { target_id }
            }
        },
        AdminCommand::Relay { action } => match action {
            RelayAction::List => AdminOperation::ListRelayTraffic,
            RelayAction::Close { session_id } => AdminOperation::CloseRelaySession { session_id },
        },
    };
    match &mut operation {
        AdminOperation::SetUserEnabled { user_id, .. }
        | AdminOperation::CreateApiToken { user_id, .. }
        | AdminOperation::ListApiTokens { user_id }
        | AdminOperation::AddUserKey { user_id, .. }
        | AdminOperation::ListKeys { user_id }
        | AdminOperation::ListUserRoles { user_id } => {
            *user_id = user_id.trim().to_ascii_lowercase();
        }
        AdminOperation::SetUserRoles { user_id, role_ids } => {
            *user_id = user_id.trim().to_ascii_lowercase();
            for role_id in role_ids {
                *role_id = role_id.trim().to_ascii_lowercase();
            }
        }
        AdminOperation::DeleteRole { role_id } | AdminOperation::ListRoleGrants { role_id } => {
            *role_id = role_id.trim().to_ascii_lowercase();
        }
        AdminOperation::GrantTarget {
            role_id, target_id, ..
        }
        | AdminOperation::RevokeTarget {
            role_id, target_id, ..
        } => {
            *role_id = role_id.trim().to_ascii_lowercase();
            *target_id = target_id.trim().to_ascii_lowercase();
        }
        AdminOperation::RenameTarget { target_id, .. }
        | AdminOperation::SetTargetEnabled { target_id, .. }
        | AdminOperation::DeleteTarget { target_id }
        | AdminOperation::IssueEnrollment { target_id } => {
            *target_id = target_id.trim().to_ascii_lowercase();
        }
        _ => {}
    }
    let token = auth::valid_access_token(context).await?;
    let response = context
        .api
        .admin(&token, &AdminRequest { operation })
        .await?;
    print_response(&response, json)
}

fn print_response(response: &AdminResponse, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
        return Ok(());
    }
    match response {
        AdminResponse::Ok => println!("操作完成。"),
        AdminResponse::Users(users) => print_users(users),
        AdminResponse::RelayTraffic(traffic) => print_relay_traffic(traffic),
        AdminResponse::RelaySessionClosed {
            session_id,
            disconnected_relay_connections,
        } => println!(
            "已关闭 relay SSH session {session_id}，断开 {disconnected_relay_connections} 条 relay endpoint 连接。"
        ),
        AdminResponse::ApiTokenIssued { api_token, token } => {
            println!(
                "API JWT for user {} ({}) — save it now; it is shown once:\n{token}",
                api_token.user_id, api_token.label
            );
        }
        AdminResponse::ApiTokens(tokens) => print_api_tokens(tokens),
        AdminResponse::User(user) => println!(
            "用户 {}\t{}\t{}",
            user.user_id,
            user.username,
            if user.enabled { "enabled" } else { "disabled" }
        ),
        AdminResponse::Keys(keys) => print_keys(keys),
        AdminResponse::Role(role) => println!("角色 {}\t{}", role.role_id, role.name),
        AdminResponse::Roles(roles) | AdminResponse::UserRoles(roles) => {
            println!("角色列表：");
            for role in roles {
                println!("{}\t{}", role.role_id, role.name);
            }
        }
        AdminResponse::Grants(grants) => print_grants(grants),
        AdminResponse::TargetCreated {
            target,
            enrollment_token,
        } => {
            println!("目标已创建：");
            print_target(target);
            println!("一次性 enrollment code：{enrollment_token}");
        }
        AdminResponse::Targets(targets) => print_targets(targets),
        AdminResponse::EnrollmentIssued {
            target_id,
            enrollment_token,
        } => println!("目标 {target_id} 的一次性 enrollment code：{enrollment_token}"),
    }
    Ok(())
}

fn print_users(users: &[UserView]) {
    println!("用户列表：");
    for user in users {
        print_user(user);
    }
}

fn print_api_tokens(tokens: &[ApiTokenView]) {
    println!("API token list:");
    for token in tokens {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            token.token_id,
            token.user_id,
            token.label,
            token.expires_at.map_or_else(
                || "never expires".to_owned(),
                |expires_at| { format!("expires at {expires_at}") }
            ),
            if token.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            }
        );
    }
}

fn print_user(user: &UserView) {
    println!(
        "{}\t{}",
        user.user_id,
        if user.enabled { "enabled" } else { "disabled" }
    );
}

fn print_relay_traffic(traffic: &RelayTrafficView) {
    if !traffic.enabled {
        println!("Private relay 未启用，当前没有可查询的 relay 流量。");
        return;
    }
    println!(
        "Relay payload 流量（{} ms 窗口）：ingress {} B ({:.1} B/s)，egress {} B ({:.1} B/s)",
        traffic.sample_duration_ms,
        traffic.bytes_received,
        traffic.bytes_received_per_second,
        traffic.bytes_sent,
        traffic.bytes_sent_per_second,
    );
    println!(
        "Relay endpoint 连接 {} 条；映射到 SSH session {} 个。",
        traffic.relay_connection_count, traffic.ssh_session_count
    );
    for connection in &traffic.connections {
        match &connection.metadata {
            Some(metadata) => {
                let side = match metadata.endpoint_side {
                    RelayEndpointSide::Client => "client",
                    RelayEndpointSide::Target => "target",
                };
                let phase = match metadata.session_phase {
                    RelaySessionPhase::Pending => "pending",
                    RelaySessionPhase::Active => "active",
                    RelaySessionPhase::Closed => "closed",
                };
                println!(
                    "endpoint {} connection {} {side} session={} phase={} user={} target={} active={} ingress={} B ({:.1} B/s) egress={} B ({:.1} B/s)",
                    connection.endpoint_id,
                    connection.connection_id,
                    metadata.session_id,
                    phase,
                    metadata.username,
                    metadata.target_name,
                    connection.active,
                    connection.bytes_received,
                    connection.bytes_received_per_second,
                    connection.bytes_sent,
                    connection.bytes_sent_per_second,
                );
            }
            None => println!(
                "endpoint {} connection {} unknown (unmapped) active={} ingress={} B ({:.1} B/s) egress={} B ({:.1} B/s)",
                connection.endpoint_id,
                connection.connection_id,
                connection.active,
                connection.bytes_received,
                connection.bytes_received_per_second,
                connection.bytes_sent,
                connection.bytes_sent_per_second,
            ),
        }
    }
}

fn print_keys(keys: &[UserKeyView]) {
    println!("SSH 公钥列表：");
    for key in keys {
        println!(
            "{}\t{}\t{}\t{}",
            key.key_id, key.user_id, key.label, key.public_key
        );
    }
}

fn print_grants(grants: &[RoleGrantView]) {
    println!("角色授权列表：");
    for grant in grants {
        println!(
            "{}\t{}\t{:?}",
            grant.role_id, grant.target_id, grant.permission
        );
    }
}

fn print_targets(targets: &[TargetView]) {
    println!("目标列表：");
    for target in targets {
        print_target(target);
    }
}

fn print_target(target: &TargetView) {
    println!(
        "{}\t{}\t{}\t{}",
        target.target_id,
        target.name,
        if target.enabled {
            "enabled"
        } else {
            "disabled"
        },
        if target.online { "online" } else { "offline" }
    );
}

fn print_help() {
    let mut command = AdminLine::command();
    let mut help = Vec::new();
    let _ = command.write_help(&mut help);
    println!("管理命令：\n{}", String::from_utf8_lossy(&help));
    println!(
        "输入 users / tokens / keys / roles / grants / targets / relay 后按 Tab 补全，输入 exit 退出。"
    );
}

fn format_error(error: &anyhow::Error) -> String {
    error.to_string()
}

struct AdminHelper;

impl Helper for AdminHelper {}
impl Hinter for AdminHelper {
    type Hint = String;
}
impl Highlighter for AdminHelper {}
impl Validator for AdminHelper {
    fn validate(&self, _ctx: &mut ValidationContext) -> rustyline::Result<ValidationResult> {
        Ok(ValidationResult::Valid(None))
    }
}

impl Completer for AdminHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &LineContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let prefix_line = &line[..pos];
        let start = prefix_line.rfind(' ').map_or(0, |index| index + 1);
        let partial = &prefix_line[start..];
        let words = prefix_line[..start].split_whitespace().collect::<Vec<_>>();
        let options: &[&str] = match words.as_slice() {
            [] => &[
                "users", "tokens", "keys", "roles", "grants", "targets", "relay", "help", "exit",
            ],
            ["users"] => &["list", "create", "disable", "enable", "roles", "show-roles"],
            ["tokens"] => &["create", "list", "revoke"],
            ["keys"] => &["list", "add", "remove"],
            ["roles"] => &["list", "create", "delete"],
            ["grants"] => &["list", "add", "remove"],
            ["targets"] => &[
                "list",
                "create",
                "rename",
                "enable",
                "disable",
                "delete",
                "issue-enrollment",
            ],
            ["relay"] => &["list", "close"],
            _ => &[],
        };
        Ok((
            start,
            options
                .iter()
                .filter(|option| option.starts_with(partial))
                .map(|option| Pair {
                    display: (*option).to_owned(),
                    replacement: (*option).to_owned(),
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_parser_accepts_one_shot_json_operations_and_help_lists_groups() {
        let top_level =
            crate::client::Cli::try_parse_from(["kmesh", "admin", "--json", "relay", "list"])
                .expect("parse one-shot relay JSON operation");
        assert!(matches!(
            top_level.command,
            crate::client::Command::Admin(AdminArgs {
                json: true,
                command: Some(AdminCommand::Relay {
                    action: RelayAction::List
                })
            })
        ));

        let user_id = "alice";
        let parsed = AdminLine::try_parse_from(["admin", "--json", "users", "disable", user_id])
            .expect("parse one-shot JSON admin operation");
        assert!(parsed.json);
        assert!(matches!(
            parsed.command,
            Some(AdminCommand::Users {
                action: UserAction::Disable { .. }
            })
        ));

        let session_id = uuid::Uuid::new_v4();
        let parsed = AdminLine::try_parse_from([
            "admin",
            "--json",
            "relay",
            "close",
            &session_id.to_string(),
        ])
        .expect("parse relay close operation");
        assert!(matches!(
            parsed.command,
            Some(AdminCommand::Relay {
                action: RelayAction::Close { session_id: id }
            }) if id == session_id
        ));

        let help = AdminLine::command().render_help().to_string();
        for group in [
            "users", "tokens", "keys", "roles", "grants", "targets", "relay",
        ] {
            assert!(help.contains(group), "admin help lists {group}");
        }
    }

    #[test]
    fn admin_repl_completion_covers_each_operation_group() {
        let history = rustyline::history::DefaultHistory::new();
        let context = LineContext::new(&history);
        let helper = AdminHelper;
        for (line, expected) in [
            ("", "users"),
            ("", "tokens"),
            ("users ", "roles"),
            ("tokens ", "revoke"),
            ("keys ", "remove"),
            ("roles ", "delete"),
            ("grants ", "remove"),
            ("targets ", "issue-enrollment"),
            ("relay ", "close"),
        ] {
            let (_, candidates) = helper
                .complete(line, line.len(), &context)
                .expect("complete admin command");
            assert!(
                candidates
                    .iter()
                    .any(|candidate| candidate.replacement == expected),
                "completion for {line:?} includes {expected}"
            );
        }
    }
}
