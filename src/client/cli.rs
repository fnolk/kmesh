use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::protocol::{SystemRole, TargetPermission};

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
        short = 'c',
        global = true,
        help = "Path to the configuration file (default ~/.kmesh/config.toml)"
    )]
    pub config: Option<PathBuf>,
    #[arg(
        long,
        short = 'd',
        global = true,
        help = "Directory for local or server data (default ~/.cache/kmesh)"
    )]
    pub data_dir: Option<PathBuf>,
    #[arg(
        long,
        short = 'p',
        global = true,
        help = "Credential profile for saved tokens (default: default)"
    )]
    pub profile: Option<String>,
    #[arg(
        long,
        short = 's',
        global = true,
        help = "IP address or hostname of the kmesh server (default localhost)"
    )]
    pub server_addr: Option<String>,
    #[arg(
        long,
        short = 'P',
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
    #[command(
        visible_alias = "a",
        about = "Use user, role, group, target, token, key, and relay commands"
    )]
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
    #[arg(short = 'a', long, help = "Username for the first administrator")]
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
    #[arg(short = 't', long, help = "Target ID to enroll")]
    pub target_id: String,
    #[arg(
        short = 'e',
        long,
        allow_hyphen_values = true,
        help = "One-time enrollment code"
    )]
    pub enrollment_code: String,
}

#[derive(Debug, Args)]
pub struct AgentRunArgs {
    #[arg(short = 't', long, help = "Target ID of the enrolled agent")]
    pub target_id: String,
}

pub use crate::config::LoginMethod;

#[derive(Debug, Args, Default)]
pub struct LoginArgs {
    #[arg(
        short = 'm',
        long,
        value_enum,
        help = "Authentication method: token or public-key"
    )]
    pub method: Option<LoginMethod>,
    #[arg(short = 'u', long, help = "Account username for public-key login")]
    pub username: Option<String>,
    #[arg(
        short = 'k',
        long,
        help = "Path to the SSH private key used for public-key login"
    )]
    pub key: Option<PathBuf>,
    #[arg(
        long,
        short = 't',
        env = "KMESH_TOKEN",
        hide_env_values = true,
        help = "API token value (also read from KMESH_TOKEN)"
    )]
    pub token: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum TargetsCommand {
    #[command(visible_aliases = ["ls", "l"], about = "List available targets")]
    List,
}

#[derive(Debug, Args)]
pub struct AdminArgs {
    #[arg(short = 'j', long, global = true, help = "Show the response as JSON")]
    pub json: bool,
    #[command(subcommand)]
    pub command: Option<AdminCommand>,
}

#[derive(Debug, Subcommand, Clone)]
pub enum AdminCommand {
    #[command(visible_aliases = ["ls", "status", "o"], about = "Show users, access groups, targets, and credential counts")]
    Overview,
    #[command(visible_aliases = ["user", "u"], about = "Use user, platform role, and access group commands")]
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
    #[command(visible_aliases = ["token", "tk"], about = "Use API token commands")]
    Tokens {
        #[command(subcommand)]
        action: ApiTokenAction,
    },
    #[command(visible_aliases = ["key", "publickey", "pk", "k"], about = "Use SSH public key commands")]
    Keys {
        #[command(subcommand)]
        action: KeyAction,
    },
    #[command(visible_aliases = ["role", "r"], about = "Show platform roles")]
    Roles {
        #[command(subcommand)]
        action: RoleAction,
    },
    #[command(visible_aliases = ["group", "g"], about = "Use access group commands")]
    Groups {
        #[command(subcommand)]
        action: AccessGroupAction,
    },
    #[command(visible_aliases = ["grant", "gr"], about = "Use grant commands for access groups and targets")]
    Grants {
        #[command(subcommand)]
        action: GrantAction,
    },
    #[command(visible_aliases = ["target", "t"], about = "Use SSH target commands")]
    Targets {
        #[command(subcommand)]
        action: TargetAction,
    },
    #[command(visible_aliases = ["rx"], about = "Inspect and close SSH sessions that use the server relay")]
    Relay {
        #[command(subcommand)]
        action: RelayAction,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum RelayAction {
    #[command(visible_aliases = ["ls", "l"], about = "List live relay transports and server payload traffic")]
    List,
    #[command(visible_aliases = ["stop"], about = "Close a private-relay SSH session and its relay transports")]
    Close {
        #[arg(help = "SSH session ID shown by `admin relay list`")]
        session_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum ApiTokenAction {
    #[command(visible_aliases = ["new", "c"], about = "Create an API token and show its value once")]
    Create {
        #[arg(help = "Username that owns the token")]
        user_id: String,
        #[arg(short = 'l', long, help = "Label describing this token")]
        label: String,
        #[arg(
            short = 'e',
            long,
            help = "Token lifetime in seconds; omit for a long-lived token"
        )]
        expires_in: Option<u64>,
    },
    #[command(visible_aliases = ["ls", "l"], about = "List a user's API tokens")]
    List {
        #[arg(help = "Username (user ID)")]
        user_id: String,
    },
    #[command(visible_aliases = ["rm"], about = "Revoke an API token")]
    Revoke {
        #[arg(help = "ID of the token to revoke")]
        token_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum UserAction {
    #[command(
        visible_alias = "s",
        about = "Show the user and its access relationships"
    )]
    Show {
        #[arg(help = "User ID")]
        user_id: String,
    },
    #[command(visible_aliases = ["ls", "l"], about = "List user accounts")]
    List,
    #[command(visible_aliases = ["new", "c"], about = "Create a user account")]
    Create {
        #[arg(help = "Username for the new account")]
        username: String,
    },
    #[command(visible_aliases = ["off"], about = "Disable a user account")]
    Disable {
        #[arg(help = "Username (user ID) to disable")]
        user_id: String,
    },
    #[command(visible_aliases = ["on"], about = "Enable a user account")]
    Enable {
        #[arg(help = "Username (user ID) to enable")]
        user_id: String,
    },
    #[command(visible_alias = "set-role", about = "Set the platform role for a user")]
    Roles {
        #[arg(help = "Username (user ID) to update")]
        user_id: String,
        #[arg(value_enum, help = "Platform role: member or admin")]
        system_role: SystemRole,
    },
    #[command(
        visible_alias = "set-groups",
        about = "Set access groups for a user. To remove all groups, use an empty group ID list."
    )]
    Groups {
        #[arg(help = "Username (user ID) to update")]
        user_id: String,
        #[arg(help = "Access group IDs to set")]
        group_ids: Vec<String>,
    },
    #[command(about = "Show access groups for a user")]
    ShowGroups {
        #[arg(help = "Username (user ID)")]
        user_id: String,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum KeyAction {
    #[command(visible_aliases = ["ls", "l"], about = "List a user's SSH public keys")]
    List {
        #[arg(help = "Username (user ID)")]
        user_id: String,
    },
    #[command(visible_aliases = ["a"], about = "Add an SSH public key to a user")]
    Add {
        #[arg(help = "Username (user ID)")]
        user_id: String,
        #[arg(help = "Path to the SSH public key file")]
        public_key_file: PathBuf,
        #[arg(
            short = 'l',
            long,
            default_value = "",
            help = "Label for the public key"
        )]
        label: String,
    },
    #[command(visible_aliases = ["rm"], about = "Remove an SSH public key")]
    Remove {
        #[arg(help = "ID of the key to remove")]
        key_id: Uuid,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum RoleAction {
    #[command(visible_aliases = ["ls", "l"], about = "Show platform roles")]
    List,
}

#[derive(Debug, Subcommand, Clone)]
pub enum AccessGroupAction {
    #[command(
        visible_alias = "s",
        about = "Show the access group and its access relationships"
    )]
    Show {
        #[arg(help = "Access group ID")]
        group_id: String,
    },
    #[command(visible_aliases = ["ls", "l"], about = "Show access groups")]
    List,
    #[command(visible_aliases = ["new", "c"], about = "Create an access group")]
    Create {
        #[arg(help = "Name of the access group")]
        name: String,
    },
    #[command(visible_aliases = ["rm"], about = "Delete an access group")]
    Delete {
        #[arg(help = "Access group ID to delete")]
        group_id: String,
    },
}

#[derive(Debug, Subcommand, Clone)]
pub enum GrantAction {
    #[command(visible_aliases = ["ls", "l"], about = "Show grants for an access group")]
    List {
        #[arg(help = "Access group ID")]
        group_id: String,
    },
    #[command(visible_aliases = ["a"], about = "Give an access group permission to connect to a target")]
    Add {
        #[arg(help = "Access group ID")]
        group_id: String,
        #[arg(help = "Target ID")]
        target_id: String,
        #[arg(short = 'x', long, value_enum, default_value_t = PermissionArg::SshConnect, help = "Permission")]
        permission: PermissionArg,
    },
    #[command(visible_aliases = ["rm"], about = "Remove an access group grant for a target")]
    Remove {
        #[arg(help = "Access group ID")]
        group_id: String,
        #[arg(help = "Target ID")]
        target_id: String,
        #[arg(short = 'x', long, value_enum, default_value_t = PermissionArg::SshConnect, help = "Permission")]
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
    #[command(
        visible_alias = "s",
        about = "Show the target and its access relationships"
    )]
    Show {
        #[arg(help = "Target ID")]
        target_id: String,
    },
    #[command(visible_aliases = ["ls", "l"], about = "List SSH targets")]
    List,
    #[command(visible_aliases = ["new", "c"], about = "Create an SSH target")]
    Create {
        #[arg(help = "Name of the target")]
        name: String,
    },
    #[command(visible_aliases = ["mv"], about = "Rename an SSH target")]
    Rename {
        #[arg(help = "Target ID")]
        target_id: String,
        #[arg(help = "New name for the target")]
        name: String,
    },
    #[command(visible_aliases = ["on"], about = "Enable an SSH target")]
    Enable {
        #[arg(help = "Target ID to enable")]
        target_id: String,
    },
    #[command(visible_aliases = ["off"], about = "Disable an SSH target")]
    Disable {
        #[arg(help = "Target ID to disable")]
        target_id: String,
    },
    #[command(visible_aliases = ["rm"], about = "Delete an SSH target")]
    Delete {
        #[arg(help = "Target ID to delete")]
        target_id: String,
    },
    #[command(visible_aliases = ["enroll", "en"], about = "Issue a one-time enrollment code for a target")]
    IssueEnrollment {
        #[arg(help = "Target ID")]
        target_id: String,
    },
}
