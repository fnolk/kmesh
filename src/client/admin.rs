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
    AccessGroupView, AdminOperation, AdminRequest, AdminResponse, ApiTokenView, GroupGrantView,
    RelayEndpointSide, RelaySessionPhase, RelayTrafficView, SystemRole, TargetView, UserKeyView,
    UserView,
};

use super::{
    ClientContext,
    admin_view::{self, Selection},
    auth,
    cli::{
        AccessGroupAction, AdminArgs, AdminCommand, ApiTokenAction, GrantAction, KeyAction,
        RelayAction, RoleAction, TargetAction, UserAction,
    },
    output::{cell, render_table, state},
};

#[derive(Debug, Parser)]
#[command(
    name = "admin",
    about = "Use user, role, group, target, token, key, and relay commands",
    disable_help_subcommand = true
)]
struct AdminLine {
    #[arg(short = 'j', long, global = true, help = "Show the response as JSON")]
    json: bool,
    #[command(subcommand)]
    command: Option<AdminCommand>,
}

pub async fn run(context: &ClientContext, args: &AdminArgs) -> Result<()> {
    let token = auth::valid_access_token(context).await?;
    let identity = context.api.me(&token).await?;
    anyhow::ensure!(
        identity.system_role == SystemRole::Admin,
        "The current user does not have the admin platform role."
    );
    if let Some(command) = &args.command {
        execute(context, command.clone(), args.json).await
    } else if args.json {
        admin_view::run(context, Selection::Overview, true).await
    } else {
        repl(context, &identity.username).await
    }
}

async fn repl(context: &ClientContext, username: &str) -> Result<()> {
    let mut editor = Editor::<AdminHelper, rustyline::history::DefaultHistory>::new()?;
    editor.set_helper(Some(AdminHelper));
    println!("Server: {}", context.api.issuer());
    println!("User: {}", cell(username));
    println!("Platform role: admin");
    println!(
        "Use ls to show the overview. Use help to list commands. Use exit to close the shell."
    );
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
                    eprintln!(
                        "Error: The command has an open quote. Close the quote and try again."
                    );
                    continue;
                };
                let mut argv = vec!["admin".to_owned()];
                argv.extend(words);
                match AdminLine::try_parse_from(argv) {
                    Ok(parsed) => {
                        if let Some(command) = parsed.command
                            && let Err(error) = execute(context, command, parsed.json).await
                        {
                            if is_forbidden(&error) {
                                return Err(error)
                                    .context("Admin access was revoked. The shell is closed.");
                            }
                            eprintln!("{}", format_error(&error));
                        }
                    }
                    Err(error) if error.use_stderr() => {
                        eprintln!("{}", error.render().to_string().trim())
                    }
                    Err(error) => println!("{}", error.render().to_string().trim()),
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => return Ok(()),
            Err(error) => return Err(error).context("read admin command"),
        }
    }
}

async fn execute(context: &ClientContext, command: AdminCommand, json: bool) -> Result<()> {
    let mut operation = match command {
        AdminCommand::Overview => {
            return admin_view::run(context, Selection::Overview, json).await;
        }
        AdminCommand::Users { action } => match action {
            UserAction::Show { user_id } => {
                return admin_view::run(context, Selection::User(user_id), json).await;
            }
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
            UserAction::Roles {
                user_id,
                system_role,
            } => AdminOperation::SetUserSystemRole {
                user_id,
                system_role,
            },
            UserAction::Groups { user_id, group_ids } => {
                AdminOperation::SetUserAccessGroups { user_id, group_ids }
            }
            UserAction::ShowGroups { user_id } => AdminOperation::ListUserAccessGroups { user_id },
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
        },
        AdminCommand::Groups { action } => match action {
            AccessGroupAction::Show { group_id } => {
                return admin_view::run(context, Selection::AccessGroup(group_id), json).await;
            }
            AccessGroupAction::List => AdminOperation::ListGroups,
            AccessGroupAction::Create { name } => AdminOperation::CreateAccessGroup { name },
            AccessGroupAction::Delete { group_id } => {
                AdminOperation::DeleteAccessGroup { group_id }
            }
        },
        AdminCommand::Grants { action } => match action {
            GrantAction::List { group_id } => AdminOperation::ListGroupGrants { group_id },
            GrantAction::Add {
                group_id,
                target_id,
                permission,
            } => AdminOperation::GrantTarget {
                group_id,
                target_id,
                permission: permission.into(),
            },
            GrantAction::Remove {
                group_id,
                target_id,
                permission,
            } => AdminOperation::RevokeTarget {
                group_id,
                target_id,
                permission: permission.into(),
            },
        },
        AdminCommand::Targets { action } => match action {
            TargetAction::Show { target_id } => {
                return admin_view::run(context, Selection::Target(target_id), json).await;
            }
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
        | AdminOperation::SetUserSystemRole { user_id, .. }
        | AdminOperation::CreateApiToken { user_id, .. }
        | AdminOperation::ListApiTokens { user_id }
        | AdminOperation::AddUserKey { user_id, .. }
        | AdminOperation::ListKeys { user_id }
        | AdminOperation::ListUserAccessGroups { user_id } => {
            *user_id = user_id.trim().to_ascii_lowercase();
        }
        AdminOperation::SetUserAccessGroups { user_id, group_ids } => {
            *user_id = user_id.trim().to_ascii_lowercase();
            for group_id in group_ids {
                *group_id = group_id.trim().to_ascii_lowercase();
            }
        }
        AdminOperation::DeleteAccessGroup { group_id }
        | AdminOperation::ListGroupGrants { group_id } => {
            *group_id = group_id.trim().to_ascii_lowercase();
        }
        AdminOperation::GrantTarget {
            group_id,
            target_id,
            ..
        }
        | AdminOperation::RevokeTarget {
            group_id,
            target_id,
            ..
        } => {
            *group_id = group_id.trim().to_ascii_lowercase();
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

fn is_forbidden(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<super::api::ApiFailure>()
            .is_some_and(|failure| {
                matches!(failure, super::api::ApiFailure::Server { status: 403, .. })
            })
    })
}

fn print_response(response: &AdminResponse, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
    } else {
        print!("{}", render_response(response));
    }
    Ok(())
}

fn render_response(response: &AdminResponse) -> String {
    match response {
        AdminResponse::Ok => "Operation complete.\n".to_owned(),
        AdminResponse::Users(users) => render_users(users),
        AdminResponse::RelayTraffic(traffic) => render_relay_traffic(traffic),
        AdminResponse::RelaySessionClosed {
            session_id,
            disconnected_relay_connections,
        } => format!(
            "Relay SSH session closed: {session_id}\nRelay connections closed: {disconnected_relay_connections}\n"
        ),
        AdminResponse::ApiTokenIssued { api_token, token } => {
            let mut output = render_api_tokens(std::slice::from_ref(api_token));
            output.push_str("Save the API token value now. You cannot show this value again.\n");
            output.push_str(&cell(token));
            output.push('\n');
            output
        }
        AdminResponse::ApiTokens(tokens) => render_api_tokens(tokens),
        AdminResponse::User(user) => render_users(std::slice::from_ref(user)),
        AdminResponse::Keys(keys) => render_keys(keys),
        AdminResponse::Roles(roles) => render_roles(roles),
        AdminResponse::UserSystemRole(role) => format!("Platform role: {}\n", role.as_str()),
        AdminResponse::AccessGroup(access_group) => {
            render_access_groups(std::slice::from_ref(access_group))
        }
        AdminResponse::AccessGroups(access_groups)
        | AdminResponse::UserAccessGroups(access_groups) => render_access_groups(access_groups),
        AdminResponse::Grants(grants) => render_grants(grants),
        AdminResponse::TargetCreated {
            target,
            enrollment_token,
        } => format!(
            "{}One-time enrollment code: {}\n",
            render_targets(std::slice::from_ref(target)),
            cell(enrollment_token)
        ),
        AdminResponse::Targets(targets) => render_targets(targets),
        AdminResponse::EnrollmentIssued {
            target_id,
            enrollment_token,
        } => format!(
            "Target: {}\nOne-time enrollment code: {}\n",
            cell(target_id),
            cell(enrollment_token)
        ),
    }
}

fn render_users(users: &[UserView]) -> String {
    let mut users = users.iter().collect::<Vec<_>>();
    users.sort_by_key(|user| &user.user_id);
    render_table(
        "Users",
        &["USER", "NAME", "STATE", "PLATFORM ROLE"],
        users
            .into_iter()
            .map(|user| {
                vec![
                    user.user_id.clone(),
                    user.username.clone(),
                    state(user.enabled).into(),
                    user.system_role.as_str().into(),
                ]
            })
            .collect(),
    )
}

fn render_access_groups(access_groups: &[AccessGroupView]) -> String {
    let mut access_groups = access_groups.iter().collect::<Vec<_>>();
    access_groups.sort_by_key(|access_group| &access_group.group_id);
    render_table(
        "Access groups",
        &["GROUP ID", "NAME"],
        access_groups
            .into_iter()
            .map(|access_group| vec![access_group.group_id.clone(), access_group.name.clone()])
            .collect(),
    )
}

fn render_roles(roles: &[SystemRole]) -> String {
    render_table(
        "Roles",
        &["ROLE"],
        roles
            .iter()
            .map(|role| vec![role.as_str().to_owned()])
            .collect(),
    )
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs().min(i64::MAX as u64) as i64)
}

fn token_state(token: &ApiTokenView, now: i64) -> &'static str {
    if token.revoked_at.is_some() {
        "revoked"
    } else if token.expires_at.is_some_and(|expiry| expiry <= now) {
        "expired"
    } else {
        "active"
    }
}

fn render_api_tokens(tokens: &[ApiTokenView]) -> String {
    let now = unix_time();
    let mut tokens = tokens.iter().collect::<Vec<_>>();
    tokens.sort_by_key(|token| (&token.user_id, token.created_at, token.token_id));
    let mut output = render_table(
        "API tokens",
        &[
            "TOKEN ID",
            "USER",
            "LABEL",
            "STATE",
            "CREATED (UNIX S)",
            "EXPIRES (UNIX S)",
        ],
        tokens
            .into_iter()
            .map(|token| {
                vec![
                    token.token_id.to_string(),
                    token.user_id.clone(),
                    token.label.clone(),
                    token_state(token, now).into(),
                    token.created_at.to_string(),
                    token
                        .expires_at
                        .map_or_else(|| "never".into(), |time| time.to_string()),
                ]
            })
            .collect(),
    );
    output
        .push_str("Token state excludes user state. A disabled user cannot use an active token.\n");
    output
}

fn key_fingerprint(key: &str) -> String {
    ssh_key::PublicKey::from_openssh(key).map_or_else(
        |_| "invalid key".into(),
        |key| key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    )
}

fn render_keys(keys: &[UserKeyView]) -> String {
    let mut keys = keys.iter().collect::<Vec<_>>();
    keys.sort_by_key(|key| (&key.user_id, key.key_id));
    render_table(
        "SSH public keys",
        &["KEY ID", "USER", "LABEL", "FINGERPRINT (SHA256)"],
        keys.into_iter()
            .map(|key| {
                vec![
                    key.key_id.to_string(),
                    key.user_id.clone(),
                    key.label.clone(),
                    key_fingerprint(&key.public_key),
                ]
            })
            .collect(),
    )
}

fn render_grants(grants: &[GroupGrantView]) -> String {
    let mut grants = grants.iter().collect::<Vec<_>>();
    grants.sort_by_key(|grant| (&grant.group_id, &grant.target_id));
    render_table(
        "Grants",
        &["GROUP ID", "TARGET", "PERMISSION"],
        grants
            .into_iter()
            .map(|grant| {
                vec![
                    grant.group_id.clone(),
                    grant.target_id.clone(),
                    "ssh_connect".into(),
                ]
            })
            .collect(),
    )
}

fn render_targets(targets: &[TargetView]) -> String {
    let mut targets = targets.iter().collect::<Vec<_>>();
    targets.sort_by_key(|target| &target.target_id);
    render_table(
        "Targets",
        &["TARGET", "NAME", "STATE", "CONNECTION"],
        targets
            .into_iter()
            .map(|target| {
                vec![
                    target.target_id.clone(),
                    target.name.clone(),
                    state(target.enabled).into(),
                    if target.online { "online" } else { "offline" }.into(),
                ]
            })
            .collect(),
    )
}

fn render_relay_traffic(traffic: &RelayTrafficView) -> String {
    if !traffic.enabled {
        return "Private relay: disabled. No traffic data.\n".into();
    }
    let mut output = format!(
        "Relay traffic\nSample: {} ms  Connections: {}  SSH sessions: {}\nReceived: {} B ({:.1} B/s)  Sent: {} B ({:.1} B/s)\n",
        traffic.sample_duration_ms,
        traffic.relay_connection_count,
        traffic.ssh_session_count,
        traffic.bytes_received,
        traffic.bytes_received_per_second,
        traffic.bytes_sent,
        traffic.bytes_sent_per_second
    );
    let mut connections = traffic.connections.iter().collect::<Vec<_>>();
    connections.sort_by_key(|connection| (&connection.endpoint_id, connection.connection_id));
    output.push_str(&render_table(
        "Relay connections",
        &[
            "ENDPOINT",
            "CONNECTION",
            "SSH SESSION",
            "SIDE",
            "PHASE",
            "USER",
            "TARGET",
            "ACTIVE",
            "RX B",
            "RX B/s",
            "TX B",
            "TX B/s",
        ],
        connections
            .into_iter()
            .map(|connection| {
                let (session, side, phase, user, target) =
                    connection.metadata.as_ref().map_or_else(
                        || ("-".into(), "unknown", "unknown", "-".into(), "-".into()),
                        |metadata| {
                            (
                                metadata.session_id.to_string(),
                                match metadata.endpoint_side {
                                    RelayEndpointSide::Client => "client",
                                    RelayEndpointSide::Target => "target",
                                },
                                match metadata.session_phase {
                                    RelaySessionPhase::Pending => "pending",
                                    RelaySessionPhase::Active => "active",
                                    RelaySessionPhase::Closed => "closed",
                                },
                                metadata.user_id.clone(),
                                metadata.target_id.clone(),
                            )
                        },
                    );
                vec![
                    connection.endpoint_id.clone(),
                    connection.connection_id.to_string(),
                    session,
                    side.into(),
                    phase.into(),
                    user,
                    target,
                    if connection.active { "yes" } else { "no" }.into(),
                    connection.bytes_received.to_string(),
                    format!("{:.1}", connection.bytes_received_per_second),
                    connection.bytes_sent.to_string(),
                    format!("{:.1}", connection.bytes_sent_per_second),
                ]
            })
            .collect(),
    ));
    output
}

fn print_help() {
    let mut command = AdminLine::command();
    let mut help = Vec::new();
    let _ = command.write_help(&mut help);
    println!("{}", String::from_utf8_lossy(&help));
    println!("Use Tab to complete a command. Use exit to stop.");
}

fn format_error(error: &anyhow::Error) -> String {
    format!("Error: {}", cell(&format!("{error:#}")))
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
        let mut command = AdminLine::command();
        for word in words {
            if word.starts_with('-') {
                continue;
            }
            let next = command
                .get_subcommands()
                .find(|subcommand| {
                    subcommand.get_name() == word
                        || subcommand.get_all_aliases().any(|alias| alias == word)
                })
                .cloned();
            let Some(next) = next else {
                if command.get_subcommands().next().is_none() {
                    break;
                }
                return Ok((start, Vec::new()));
            };
            command = next;
        }
        let mut options = Vec::new();
        for subcommand in command.get_subcommands() {
            options.push(subcommand.get_name().to_owned());
            options.extend(subcommand.get_visible_aliases().map(str::to_owned));
        }
        for argument in command.get_arguments() {
            if let Some(long) = argument.get_long() {
                options.push(format!("--{long}"));
            }
            if let Some(short) = argument.get_short() {
                options.push(format!("-{short}"));
            }
        }
        if command.get_name() == "admin" {
            options.extend(["help", "exit", "quit"].map(str::to_owned));
        }
        options.sort();
        options.dedup();
        Ok((
            start,
            options
                .iter()
                .filter(|option| option.starts_with(partial))
                .map(|option| Pair {
                    display: option.clone(),
                    replacement: option.clone(),
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_states_distinguish_expiry_and_revocation() {
        let mut token = ApiTokenView {
            token_id: uuid::Uuid::nil(),
            user_id: "alice".into(),
            label: "laptop".into(),
            created_at: 1,
            expires_at: Some(100),
            revoked_at: None,
        };
        assert_eq!(token_state(&token, 99), "active");
        assert_eq!(token_state(&token, 100), "expired");
        token.revoked_at = Some(90);
        assert_eq!(token_state(&token, 100), "revoked");
        token.expires_at = None;
        token.revoked_at = None;
        assert_eq!(token_state(&token, 100), "active");
    }

    #[test]
    fn output_has_complete_ids_and_no_raw_public_keys() {
        let key_id = uuid::Uuid::new_v4();
        let output = render_keys(&[UserKeyView {
            key_id,
            user_id: "alice".into(),
            label: "line\n\x1b[31m".into(),
            public_key: "untrusted-key-blob".into(),
        }]);
        assert!(output.contains(&key_id.to_string()));
        assert!(output.contains("FINGERPRINT"));
        assert!(output.contains("invalid key"));
        assert!(!output.contains("untrusted-key-blob"));
        assert!(!output.contains('\x1b'));
    }

    #[test]
    fn all_empty_response_tables_are_explicit() {
        for response in [
            AdminResponse::Users(vec![]),
            AdminResponse::AccessGroups(vec![]),
            AdminResponse::Targets(vec![]),
            AdminResponse::Keys(vec![]),
            AdminResponse::ApiTokens(vec![]),
            AdminResponse::Grants(vec![]),
        ] {
            let output = render_response(&response);
            assert!(output.contains("(0)\nNo records.\n"));
            assert!(!output.contains('\t'));
        }
    }

    #[test]
    fn explicit_short_commands_match_canonical_commands() {
        for (long, short) in [
            (vec!["admin", "overview"], vec!["a", "ls"]),
            (
                vec!["admin", "users", "show", "alice"],
                vec!["a", "u", "s", "alice"],
            ),
            (
                vec!["admin", "groups", "show", "engineers"],
                vec!["a", "g", "s", "engineers"],
            ),
            (
                vec!["admin", "targets", "show", "build"],
                vec!["a", "t", "s", "build"],
            ),
            (
                vec![
                    "admin",
                    "tokens",
                    "create",
                    "alice",
                    "--label",
                    "laptop",
                    "--expires-in",
                    "60",
                ],
                vec!["a", "tk", "c", "alice", "-l", "laptop", "-e", "60"],
            ),
            (
                vec![
                    "admin",
                    "grants",
                    "add",
                    "engineers",
                    "build",
                    "--permission",
                    "ssh-connect",
                ],
                vec!["a", "gr", "a", "engineers", "build", "-x", "ssh-connect"],
            ),
            (
                vec!["admin", "keys", "list", "alice"],
                vec!["a", "pk", "ls", "alice"],
            ),
        ] {
            let long =
                crate::client::Cli::try_parse_from(std::iter::once("kmesh").chain(long)).unwrap();
            let short =
                crate::client::Cli::try_parse_from(std::iter::once("kmesh").chain(short)).unwrap();
            assert_eq!(
                format!("{:?}", long.command),
                format!("{:?}", short.command)
            );
        }
        assert!(crate::client::Cli::try_parse_from(["kmesh", "a", "us", "list"]).is_err());
        crate::client::Cli::command().debug_assert();
        AdminLine::command().debug_assert();
        assert!(
            AdminLine::try_parse_from(["admin", "u", "ls", "-j"])
                .unwrap()
                .json
        );
    }

    #[test]
    fn global_short_flags_do_not_conflict_with_admin_flags() {
        let parsed = crate::client::Cli::try_parse_from([
            "kmesh",
            "a",
            "tk",
            "c",
            "alice",
            "-l",
            "laptop",
            "-e",
            "60",
            "-p",
            "work",
            "-s",
            "example.test",
            "-P",
            "9555",
            "-d",
            "/tmp/data",
            "-c",
            "/tmp/config",
            "-j",
        ])
        .unwrap();
        assert_eq!(parsed.profile.as_deref(), Some("work"));
        assert_eq!(parsed.server_addr.as_deref(), Some("example.test"));
        assert_eq!(parsed.server_port, Some(9555));
    }

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
        assert!(matches!(
            crate::client::Cli::try_parse_from([
                "kmesh", "admin", "users", "roles", user_id, "member",
            ])
            .unwrap()
            .command,
            crate::client::Command::Admin(AdminArgs {
                command: Some(AdminCommand::Users {
                    action: UserAction::Roles {
                        system_role: SystemRole::Member,
                        ..
                    }
                }),
                ..
            })
        ));
        assert!(
            crate::client::Cli::try_parse_from(["kmesh", "admin", "roles", "create", "engineers"])
                .is_err()
        );
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
            "users", "roles", "groups", "tokens", "keys", "grants", "targets", "relay",
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
            ("users ", "groups"),
            ("u ", "s"),
            ("tk ", "c"),
            ("tk c alice --", "--label"),
            ("tk c alice -", "-e"),
            ("pk ", "rm"),
            ("t ", "en"),
            ("", "ls"),
            ("tokens ", "revoke"),
            ("keys ", "remove"),
            ("groups ", "delete"),
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
