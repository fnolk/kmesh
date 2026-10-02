use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::protocol::TargetPermission;

#[derive(Debug, Parser)]
#[command(
    name = "kmesh",
    version,
    about = "SSH access over direct QUIC or relay",
    before_help = "kmesh 通过 SSH 专用隧道连接目标机器。"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    pub profile: Option<String>,
    #[arg(long, global = true)]
    pub server_url: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Login(LoginArgs),
    Logout,
    Targets {
        #[command(subcommand)]
        command: TargetsCommand,
    },
    SshConfig {
        target: String,
    },
    Proxy {
        target_id: Uuid,
    },
    Admin(AdminArgs),
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    Init(ServerInitArgs),
    Run(ServerRunArgs),
}

#[derive(Debug, Args)]
pub struct ServerInitArgs {
    #[arg(long)]
    pub admin: String,
    #[arg(long)]
    pub password_stdin: bool,
    #[arg(long)]
    pub issuer: String,
}

#[derive(Debug, Args)]
pub struct ServerRunArgs {
    #[arg(long)]
    pub issuer: String,
    #[arg(long, default_value = "0.0.0.0:443")]
    pub bind: SocketAddr,
    #[arg(long)]
    pub tls_cert: PathBuf,
    #[arg(long)]
    pub tls_key: PathBuf,
    #[arg(long, default_value = "0.0.0.0:3478")]
    pub stun_bind: SocketAddr,
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    Enroll(AgentEnrollArgs),
    Run(AgentRunArgs),
}

#[derive(Debug, Args)]
pub struct AgentEnrollArgs {
    #[arg(long)]
    pub target_id: Uuid,
    #[arg(long, allow_hyphen_values = true)]
    pub enrollment_code: String,
}

#[derive(Debug, Args)]
pub struct AgentRunArgs {
    #[arg(long)]
    pub target_id: Uuid,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LoginMethod {
    Password,
    PublicKey,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(long, value_enum)]
    pub method: LoginMethod,
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub password_stdin: bool,
    #[arg(long)]
    pub key: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum TargetsCommand {
    List,
}

#[derive(Debug, Args)]
pub struct AdminArgs {
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Option<AdminCommand>,
}

#[derive(Debug, Subcommand, Clone)]
pub enum AdminCommand {
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
    Keys {
        #[command(subcommand)]
        action: KeyAction,
    },
    Roles {
        #[command(subcommand)]
        action: RoleAction,
    },
    Grants {
        #[command(subcommand)]
        action: GrantAction,
    },
    Targets {
        #[command(subcommand)]
        action: TargetAction,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum UserAction {
    List,
    Create {
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    Disable {
        user_id: Uuid,
    },
    Enable {
        user_id: Uuid,
    },
    ResetPassword {
        user_id: Uuid,
        #[arg(long)]
        password_stdin: bool,
    },
    Roles {
        user_id: Uuid,
        role_ids: Vec<Uuid>,
    },
    ShowRoles {
        user_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum KeyAction {
    List {
        user_id: Uuid,
    },
    Add {
        user_id: Uuid,
        public_key: String,
        #[arg(long, default_value = "")]
        label: String,
    },
    Remove {
        key_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum RoleAction {
    List,
    Create { name: String },
    Delete { role_id: Uuid },
}

#[derive(Debug, Subcommand, Clone)]
pub enum GrantAction {
    List {
        role_id: Uuid,
    },
    Add {
        role_id: Uuid,
        target_id: Uuid,
        #[arg(long, value_enum, default_value_t = PermissionArg::SshConnect)]
        permission: PermissionArg,
    },
    Remove {
        role_id: Uuid,
        target_id: Uuid,
        #[arg(long, value_enum, default_value_t = PermissionArg::SshConnect)]
        permission: PermissionArg,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PermissionArg {
    SshConnect,
}

impl From<PermissionArg> for TargetPermission {
    fn from(_: PermissionArg) -> Self {
        TargetPermission::SshConnect
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum TargetAction {
    List,
    Create { name: String },
    Rename { target_id: Uuid, name: String },
    Enable { target_id: Uuid },
    Disable { target_id: Uuid },
    Delete { target_id: Uuid },
    IssueEnrollment { target_id: Uuid },
}
