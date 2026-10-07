use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::protocol::TargetPermission;

#[derive(Debug, Parser)]
#[command(
    name = "kmesh",
    version,
    long_version = crate::version::CLI_LONG_VERSION,
    about = "SSH access over direct QUIC or relay"
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Path to the configuration file (default ~/.kmesh/config.toml)"
    )]
    pub config: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "Directory for local or server data (default ~/.cache/kmesh)"
    )]
    pub data_dir: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "Credential profile for saved tokens (default: default)"
    )]
    pub profile: Option<String>,
    #[arg(
        long,
        global = true,
        help = "IP address or hostname of the kmesh server (default localhost)"
    )]
    pub server_addr: Option<String>,
    #[arg(
        long,
        global = true,
        help = "HTTPS port of the kmesh server (default 9443)"
    )]
    pub server_port: Option<u16>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Initialize or run the kmesh server")]
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    #[command(about = "Enroll or run an SSH agent on a target machine")]
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    #[command(about = "Sign in to a kmesh server")]
    Login(LoginArgs),
    #[command(about = "Sign out and remove the active credentials")]
    Logout,
    #[command(about = "List targets available to the current user")]
    Targets {
        #[command(subcommand)]
        command: TargetsCommand,
    },
    #[command(about = "Print an OpenSSH configuration entry for a target")]
    SshConfig {
        #[arg(help = "Target ID")]
        target: String,
    },
    #[command(about = "Open an SSH stream to a target")]
    Proxy {
        #[arg(help = "Target ID to connect to")]
        target_id: String,
    },
    #[command(about = "Manage users, SSH keys, roles, grants, targets, and relay traffic")]
    Admin(AdminArgs),
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    #[command(about = "Initialize server data and create the first administrator")]
    Init(ServerInitArgs),
    #[command(about = "Run the kmesh HTTPS and relay services")]
    Run(ServerRunArgs),
}

#[derive(Debug, Args)]
pub struct ServerInitArgs {
    #[arg(long, help = "Username for the first administrator")]
    pub admin: String,
}

#[derive(Debug, Args)]
pub struct ServerRunArgs {
    #[arg(
        long,
        help = "IP address to bind HTTPS and QAD listeners (default 0.0.0.0)"
    )]
    pub bind_addr: Option<IpAddr>,
    #[arg(long, help = "UDP port for the QAD listener (default 3478)")]
    pub udp_port: Option<u16>,
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true,
        help = "Whether to disable the private Iroh relay"
    )]
    pub disable_private_relay: Option<bool>,
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    #[command(about = "Enroll this machine as a target agent")]
    Enroll(AgentEnrollArgs),
    #[command(about = "Run the target agent")]
    Run(AgentRunArgs),
}

#[derive(Debug, Args)]
pub struct AgentEnrollArgs {
    #[arg(long, help = "Target ID to enroll")]
    pub target_id: String,
    #[arg(long, allow_hyphen_values = true, help = "One-time enrollment code")]
    pub enrollment_code: String,
}

#[derive(Debug, Args)]
pub struct AgentRunArgs {
    #[arg(long, help = "Target ID of the enrolled agent")]
    pub target_id: String,
}

pub use crate::config::LoginMethod;

#[derive(Debug, Args, Default)]
pub struct LoginArgs {
    #[arg(long, value_enum, help = "Authentication method: token or public-key")]
    pub method: Option<LoginMethod>,
    #[arg(long, help = "Account username for public-key login")]
    pub username: Option<String>,
    #[arg(long, help = "Path to the SSH private key used for public-key login")]
    pub key: Option<PathBuf>,
    #[arg(
        long,
        env = "KMESH_TOKEN",
        hide_env_values = true,
        help = "API JWT (also read from KMESH_TOKEN)"
    )]
    pub token: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum TargetsCommand {
    #[command(about = "List available targets")]
    List,
}

#[derive(Debug, Args)]
pub struct AdminArgs {
    #[arg(long, global = true, help = "Output the response as JSON")]
    pub json: bool,
    #[command(subcommand)]
    pub command: Option<AdminCommand>,
}

#[derive(Debug, Subcommand, Clone)]
pub enum AdminCommand {
    #[command(about = "Manage user accounts and role assignments")]
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
    #[command(about = "Manage API JWT tokens")]
    Tokens {
        #[command(subcommand)]
        action: ApiTokenAction,
    },
    #[command(about = "Manage user SSH public keys")]
    Keys {
        #[command(subcommand)]
        action: KeyAction,
    },
    #[command(about = "Manage authorization roles")]
    Roles {
        #[command(subcommand)]
        action: RoleAction,
    },
    #[command(about = "Manage role permissions for targets")]
    Grants {
        #[command(subcommand)]
        action: GrantAction,
    },
    #[command(about = "Manage SSH targets")]
    Targets {
        #[command(subcommand)]
        action: TargetAction,
    },
    #[command(about = "Inspect and close SSH sessions that use the server relay")]
    Relay {
        #[command(subcommand)]
        action: RelayAction,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum RelayAction {
    #[command(about = "List live relay transports and server payload traffic")]
    List,
    #[command(about = "Close a private-relay SSH session and its relay transports")]
    Close {
        #[arg(help = "SSH session ID shown by `admin relay list`")]
        session_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum ApiTokenAction {
    #[command(about = "Create and display a user's API JWT once")]
    Create {
        #[arg(help = "Username that owns the token")]
        user_id: String,
        #[arg(long, help = "Label describing this token")]
        label: String,
        #[arg(long, help = "Token lifetime in seconds; omit for a long-lived token")]
        expires_in: Option<u64>,
    },
    #[command(about = "List a user's API tokens")]
    List {
        #[arg(help = "Username (user ID)")]
        user_id: String,
    },
    #[command(about = "Revoke an API token")]
    Revoke {
        #[arg(help = "ID of the token to revoke")]
        token_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum UserAction {
    #[command(about = "List user accounts")]
    List,
    #[command(about = "Create a user account")]
    Create {
        #[arg(help = "Username for the new account")]
        username: String,
    },
    #[command(about = "Disable a user account")]
    Disable {
        #[arg(help = "Username (user ID) to disable")]
        user_id: String,
    },
    #[command(about = "Enable a user account")]
    Enable {
        #[arg(help = "Username (user ID) to enable")]
        user_id: String,
    },
    #[command(about = "Replace a user's role assignments")]
    Roles {
        #[arg(help = "Username (user ID) to update")]
        user_id: String,
        #[arg(help = "Role names (role IDs) to assign")]
        role_ids: Vec<String>,
    },
    #[command(about = "List roles assigned to a user")]
    ShowRoles {
        #[arg(help = "Username (user ID)")]
        user_id: String,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum KeyAction {
    #[command(about = "List a user's SSH public keys")]
    List {
        #[arg(help = "Username (user ID)")]
        user_id: String,
    },
    #[command(about = "Add an SSH public key to a user")]
    Add {
        #[arg(help = "Username (user ID)")]
        user_id: String,
        #[arg(help = "Path to the SSH public key file")]
        public_key_file: PathBuf,
        #[arg(long, default_value = "", help = "Label for the public key")]
        label: String,
    },
    #[command(about = "Remove an SSH public key")]
    Remove {
        #[arg(help = "ID of the key to remove")]
        key_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum RoleAction {
    #[command(about = "List authorization roles")]
    List,
    #[command(about = "Create an authorization role")]
    Create {
        #[arg(help = "Name of the role")]
        name: String,
    },
    #[command(about = "Delete an authorization role")]
    Delete {
        #[arg(help = "Role ID to delete")]
        role_id: String,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum GrantAction {
    #[command(about = "List permissions granted to a role")]
    List {
        #[arg(help = "Role ID")]
        role_id: String,
    },
    #[command(about = "Grant a role permission to access a target")]
    Add {
        #[arg(help = "Role ID")]
        role_id: String,
        #[arg(help = "Target ID")]
        target_id: String,
        #[arg(long, value_enum, default_value_t = PermissionArg::SshConnect, help = "Permission to grant")]
        permission: PermissionArg,
    },
    #[command(about = "Revoke a role's permission to access a target")]
    Remove {
        #[arg(help = "Role ID")]
        role_id: String,
        #[arg(help = "Target ID")]
        target_id: String,
        #[arg(long, value_enum, default_value_t = PermissionArg::SshConnect, help = "Permission to revoke")]
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
    #[command(about = "List SSH targets")]
    List,
    #[command(about = "Create an SSH target")]
    Create {
        #[arg(help = "Name of the target")]
        name: String,
    },
    #[command(about = "Rename an SSH target")]
    Rename {
        #[arg(help = "Target ID")]
        target_id: String,
        #[arg(help = "New name for the target")]
        name: String,
    },
    #[command(about = "Enable an SSH target")]
    Enable {
        #[arg(help = "Target ID to enable")]
        target_id: String,
    },
    #[command(about = "Disable an SSH target")]
    Disable {
        #[arg(help = "Target ID to disable")]
        target_id: String,
    },
    #[command(about = "Delete an SSH target")]
    Delete {
        #[arg(help = "Target ID to delete")]
        target_id: String,
    },
    #[command(about = "Issue a one-time enrollment code for a target")]
    IssueEnrollment {
        #[arg(help = "Target ID")]
        target_id: String,
    },
}
