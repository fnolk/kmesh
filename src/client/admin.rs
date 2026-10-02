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
    AdminOperation, AdminRequest, AdminResponse, RoleGrantView, TargetView, UserKeyView, UserView,
};

use super::{
    ClientContext, auth,
    cli::{AdminArgs, AdminCommand, GrantAction, KeyAction, RoleAction, TargetAction, UserAction},
};

#[derive(Debug, Parser)]
#[command(name = "admin", disable_help_subcommand = true)]
struct AdminLine {
    #[arg(long)]
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
    let operation = match command {
        AdminCommand::Users { action } => match action {
            UserAction::List => AdminOperation::ListUsers,
            UserAction::Create {
                username,
                password_stdin,
            } => {
                let password = read_new_password("设置新用户密码", password_stdin)?;
                AdminOperation::CreateUser { username, password }
            }
            UserAction::Disable { user_id } => AdminOperation::SetUserEnabled {
                user_id,
                enabled: false,
            },
            UserAction::Enable { user_id } => AdminOperation::SetUserEnabled {
                user_id,
                enabled: true,
            },
            UserAction::ResetPassword {
                user_id,
                password_stdin,
            } => AdminOperation::ResetPassword {
                user_id,
                password: read_new_password("重置用户密码", password_stdin)?,
            },
            UserAction::Roles { user_id, role_ids } => {
                AdminOperation::SetUserRoles { user_id, role_ids }
            }
            UserAction::ShowRoles { user_id } => AdminOperation::ListUserRoles { user_id },
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
    };
    let token = auth::valid_access_token(context).await?;
    let response = context
        .api
        .admin(&token, &AdminRequest { operation })
        .await?;
    print_response(&response, json)
}

fn read_new_password(prompt: &str, stdin: bool) -> Result<String> {
    let first = auth::read_password(&format!("请{prompt}："), stdin)?;
    let second = auth::read_password("请再输入一次：", stdin)?;
    anyhow::ensure!(first == second, "两次输入的密码不一致");
    anyhow::ensure!(!first.is_empty(), "密码不能为空");
    Ok(first)
}

fn print_response(response: &AdminResponse, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
        return Ok(());
    }
    match response {
        AdminResponse::Ok => println!("操作完成。"),
        AdminResponse::Users(users) => print_users(users),
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

fn print_user(user: &UserView) {
    println!(
        "{}\t{}\t{}",
        user.user_id,
        user.username,
        if user.enabled { "enabled" } else { "disabled" }
    );
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
    println!("输入 users / keys / roles / grants / targets 后按 Tab 补全，输入 exit 退出。");
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
                "users", "keys", "roles", "grants", "targets", "help", "exit",
            ],
            ["users"] => &[
                "list",
                "create",
                "disable",
                "enable",
                "reset-password",
                "roles",
                "show-roles",
            ],
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
