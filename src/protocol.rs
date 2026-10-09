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
pub struct ApiTokenView {
    pub token_id: Uuid,
    pub user_id: String,
    pub label: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
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
    pub target_id: String,
    pub name: String,
    pub enabled: bool,
    pub online: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserView {
    pub user_id: String,
    pub username: String,
    pub system_role: SystemRole,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeView {
    pub user_id: String,
    pub username: String,
    pub enabled: bool,
    pub system_role: SystemRole,
    pub access_groups: Vec<AccessGroupView>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum SystemRole {
    Member,
    Admin,
}

impl SystemRole {
    pub const ALL: [Self; 2] = [Self::Member, Self::Admin];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessGroupView {
    pub group_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserKeyView {
    pub key_id: Uuid,
    pub user_id: String,
    pub public_key: String,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetPermission {
    SshConnect,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupGrantView {
    pub group_id: String,
    pub target_id: String,
    pub permission: TargetPermission,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupChangeMode {
    Replace,
    Add,
    Remove,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupChange {
    pub user_id: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub lost_target_ids: Vec<String>,
    pub gained_target_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessExplanation {
    pub user_id: String,
    pub target_id: String,
    pub access_groups: Vec<String>,
    pub granting_groups: Vec<String>,
    pub blockers: Vec<String>,
    pub authorized: bool,
    pub online: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", content = "data", rename_all = "snake_case")]
pub enum AdminOperation {
    ChangeUserAccessGroups {
        user_id: String,
        group_ids: Vec<String>,
        mode: GroupChangeMode,
        dry_run: bool,
        expected: Option<GroupChange>,
    },
    ExplainAccess {
        user_id: String,
        target_id: String,
    },
    ListUsers,
    ListRelayTraffic,
    CloseRelaySession {
        session_id: Uuid,
    },
    CreateUser {
        username: String,
    },
    SetUserEnabled {
        user_id: String,
        enabled: bool,
    },
    CreateApiToken {
        user_id: String,
        label: String,
        expires_in_secs: Option<u64>,
    },
    ListApiTokens {
        user_id: String,
    },
    RevokeApiToken {
        token_id: Uuid,
    },
    AddUserKey {
        user_id: String,
        public_key: String,
        label: String,
    },
    RemoveUserKey {
        key_id: Uuid,
    },
    ListKeys {
        user_id: String,
    },
    ListRoles,
    SetUserSystemRole {
        user_id: String,
        system_role: SystemRole,
    },
    ListGroups,
    CreateAccessGroup {
        name: String,
    },
    DeleteAccessGroup {
        group_id: String,
    },
    SetUserAccessGroups {
        user_id: String,
        group_ids: Vec<String>,
    },
    ListUserAccessGroups {
        user_id: String,
    },
    GrantTarget {
        group_id: String,
        target_id: String,
        permission: TargetPermission,
    },
    RevokeTarget {
        group_id: String,
        target_id: String,
        permission: TargetPermission,
    },
    ListGroupGrants {
        group_id: String,
    },
    ListTargets,
    CreateTarget {
        name: String,
    },
    RenameTarget {
        target_id: String,
        name: String,
    },
    SetTargetEnabled {
        target_id: String,
        enabled: bool,
    },
    DeleteTarget {
        target_id: String,
    },
    IssueEnrollment {
        target_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminRequest {
    pub operation: AdminOperation,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayEndpointSide {
    Client,
    Target,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelaySessionPhase {
    Pending,
    Active,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConnectionMetadata {
    pub session_id: Uuid,
    pub user_id: String,
    pub username: String,
    pub target_id: String,
    pub target_name: String,
    pub endpoint_side: RelayEndpointSide,
    pub session_phase: RelaySessionPhase,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConnectionView {
    pub endpoint_id: String,
    pub connection_id: u64,
    pub connected_at_unix_ms: u64,
    pub active: bool,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub bytes_received_per_second: f64,
    pub bytes_sent_per_second: f64,
    pub metadata: Option<RelayConnectionMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayTrafficView {
    pub enabled: bool,
    pub sample_duration_ms: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub bytes_received_per_second: f64,
    pub bytes_sent_per_second: f64,
    pub relay_connection_count: u64,
    pub ssh_session_count: u64,
    pub connections: Vec<RelayConnectionView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum AdminResponse {
    GroupChange {
        change: GroupChange,
        applied: bool,
        access_groups: Vec<AccessGroupView>,
    },
    AccessExplanation(AccessExplanation),
    Ok,
    Users(Vec<UserView>),
    User(UserView),
    ApiTokenIssued {
        api_token: ApiTokenView,
        token: String,
    },
    ApiTokens(Vec<ApiTokenView>),
    Keys(Vec<UserKeyView>),
    Roles(Vec<SystemRole>),
    UserSystemRole(SystemRole),
    AccessGroup(AccessGroupView),
    AccessGroups(Vec<AccessGroupView>),
    UserAccessGroups(Vec<AccessGroupView>),
    Grants(Vec<GroupGrantView>),
    TargetCreated {
        target: TargetView,
        enrollment_token: String,
    },
    Targets(Vec<TargetView>),
    EnrollmentIssued {
        target_id: String,
        enrollment_token: String,
    },
    RelayTraffic(RelayTrafficView),
    RelaySessionClosed {
        session_id: Uuid,
        disconnected_relay_connections: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentEnrollmentRequest {
    pub target_id: String,
    pub enrollment_token: String,
    pub agent_endpoint_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentEnrollmentResponse {
    pub target_id: String,
    pub agent_token: String,
    pub ticket_public_key_pem: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentCredentials {
    pub target_id: String,
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
    pub sub: String,
    pub sid: Uuid,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTokenClaims {
    pub sub: String,
    pub jti: Uuid,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum AuthCredential {
    Session(Uuid),
    ApiToken(Uuid),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelTicketClaims {
    pub session_id: Uuid,
    pub user_id: String,
    pub auth_credential: AuthCredential,
    pub target_id: String,
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
        target_id: String,
        client_endpoint_id: String,
        route_mode: RouteMode,
    },
    ClientOffer {
        session_id: Uuid,
        target_id: String,
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
        target_id: String,
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
