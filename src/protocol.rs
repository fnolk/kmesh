use std::net::{SocketAddr, SocketAddrV4};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: u64,
    pub refresh_expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyChallengeRequest {
    pub username: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyChallenge {
    pub challenge_id: Uuid,
    pub challenge: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyLoginRequest {
    pub username: String,
    pub challenge_id: Uuid,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetView {
    pub target_id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub online: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserView {
    pub user_id: Uuid,
    pub username: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeView {
    pub user: UserView,
    pub roles: Vec<RoleView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleView {
    pub role_id: Uuid,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserKeyView {
    pub key_id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetPermission {
    SshConnect,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleGrantView {
    pub role_id: Uuid,
    pub target_id: Uuid,
    pub permission: TargetPermission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", content = "data", rename_all = "snake_case")]
pub enum AdminOperation {
    ListUsers,
    CreateUser {
        username: String,
        password: String,
    },
    SetUserEnabled {
        user_id: Uuid,
        enabled: bool,
    },
    ResetPassword {
        user_id: Uuid,
        password: String,
    },
    AddUserKey {
        user_id: Uuid,
        public_key: String,
        label: String,
    },
    RemoveUserKey {
        key_id: Uuid,
    },
    ListKeys {
        user_id: Uuid,
    },
    ListRoles,
    CreateRole {
        name: String,
    },
    DeleteRole {
        role_id: Uuid,
    },
    SetUserRoles {
        user_id: Uuid,
        role_ids: Vec<Uuid>,
    },
    ListUserRoles {
        user_id: Uuid,
    },
    GrantTarget {
        role_id: Uuid,
        target_id: Uuid,
        permission: TargetPermission,
    },
    RevokeTarget {
        role_id: Uuid,
        target_id: Uuid,
        permission: TargetPermission,
    },
    ListRoleGrants {
        role_id: Uuid,
    },
    ListTargets,
    CreateTarget {
        name: String,
    },
    RenameTarget {
        target_id: Uuid,
        name: String,
    },
    SetTargetEnabled {
        target_id: Uuid,
        enabled: bool,
    },
    DeleteTarget {
        target_id: Uuid,
    },
    IssueEnrollment {
        target_id: Uuid,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminRequest {
    pub operation: AdminOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok,
    Users(Vec<UserView>),
    User(UserView),
    Keys(Vec<UserKeyView>),
    Role(RoleView),
    Roles(Vec<RoleView>),
    UserRoles(Vec<RoleView>),
    Grants(Vec<RoleGrantView>),
    TargetCreated {
        target: TargetView,
        enrollment_token: String,
    },
    Targets(Vec<TargetView>),
    EnrollmentIssued {
        target_id: Uuid,
        enrollment_token: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentEnrollmentRequest {
    pub target_id: Uuid,
    pub enrollment_token: String,
    pub agent_endpoint_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentEnrollmentResponse {
    pub target_id: Uuid,
    pub agent_token: String,
    pub ticket_public_key_pem: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentCredentials {
    pub target_id: Uuid,
    pub agent_token: String,
    pub ticket_public_key_pem: String,
    pub endpoint_secret_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportInfo {
    pub private_relay_url: Option<String>,
    pub qad_port: u16,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    PrivateDirect,
    PublicDirect,
    PrivateRelay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelTicketClaims {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub login_session_id: Uuid,
    pub target_id: Uuid,
    pub client_endpoint_id: String,
    /// This ticket's target data-plane EndpointId, scoped to `session_id`.
    pub target_endpoint_id: String,
    pub route_mode: RouteMode,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
}

/// QAD results collected on the same IPv4 socket that the subsequent punch uses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadyDiscovery {
    /// Bound IPv4 socket used to obtain every observation in this result.
    pub local_socket: SocketAddrV4,
    /// Authenticated mappings reported for that same socket.
    pub observations: Vec<crate::transport::QadObservation>,
}

/// Address discovery may fail because of the current network; that is a transport result,
/// separate from ticket or identity errors.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DiscoveryResult {
    Ready {
        local_socket: SocketAddrV4,
        observations: Vec<crate::transport::QadObservation>,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum NativePlan {
    Standard,
    Handoff {
        self_observed_addr: SocketAddrV4,
        peer_observed_addr: SocketAddrV4,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SelectedPath {
    Direct { remote_address: SocketAddr },
    PrivateRelay { url: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Open {
        session_id: Uuid,
        target_id: Uuid,
        client_endpoint_id: String,
        route_mode: RouteMode,
    },
    ClientOffer {
        session_id: Uuid,
        target_id: Uuid,
        ticket: String,
        client_endpoint_id: String,
        target_endpoint_id: String,
        ticket_public_key_pem: String,
        route_mode: RouteMode,
    },
    Prepare {
        session_id: Uuid,
        route_mode: RouteMode,
        client_endpoint_id: String,
        expires_at: i64,
    },
    AgentIdentity {
        session_id: Uuid,
        route_mode: RouteMode,
        target_data_endpoint_id: String,
        signature: Vec<u8>,
    },
    IdentityAccepted {
        session_id: Uuid,
        route_mode: RouteMode,
    },
    CandidatesReady {
        session_id: Uuid,
        route_mode: RouteMode,
        discovery: DiscoveryResult,
    },
    PunchPair {
        session_id: Uuid,
        route_mode: RouteMode,
        target_endpoint_id: String,
        client_endpoint_id: String,
        peer_discovery: ReadyDiscovery,
    },
    PunchReady {
        session_id: Uuid,
        route_mode: RouteMode,
        socket_count: u16,
    },
    StartPunch {
        session_id: Uuid,
        route_mode: RouteMode,
    },
    PunchSelected {
        session_id: Uuid,
        route_mode: RouteMode,
        index: u16,
        local_socket: SocketAddrV4,
        peer_observed_addr: SocketAddrV4,
    },
    PunchFailed {
        session_id: Uuid,
        route_mode: RouteMode,
        reason: String,
    },
    ContinueNative {
        session_id: Uuid,
        route_mode: RouteMode,
        plan: NativePlan,
    },
    AgentReady {
        session_id: Uuid,
        route_mode: RouteMode,
        endpoint_addr: iroh::EndpointAddr,
    },
    ClientReady {
        session_id: Uuid,
        route_mode: RouteMode,
        client_endpoint_addr: iroh::EndpointAddr,
    },
    DialOffer {
        session_id: Uuid,
        target_id: Uuid,
        ticket: String,
        client_endpoint_id: String,
        client_endpoint_addr: iroh::EndpointAddr,
        ticket_public_key_pem: String,
        route_mode: RouteMode,
    },
    PathReady {
        session_id: Uuid,
        route_mode: RouteMode,
        path: SelectedPath,
    },
    IrohReady {
        session_id: Uuid,
        client_endpoint_id: String,
        target_data_endpoint_id: String,
        route_mode: RouteMode,
    },
    Activated {
        session_id: Uuid,
    },
    Error {
        session_id: Option<Uuid>,
        code: String,
        message: String,
    },
    Close {
        session_id: Uuid,
        reason: String,
    },
}
