use std::net::SocketAddr;

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
    pub certificate_der: Vec<u8>,
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
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuicChallenge {
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectAuthentication {
    pub ticket: String,
    pub signature: String,
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
    pub client_public_key: String,
    pub target_certificate_fingerprint: String,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Client,
    Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConnectQuery {
    pub session_id: Uuid,
    pub peer: PeerRole,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectedPath {
    Quic,
    Relay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Open {
        session_id: Uuid,
        target_id: Uuid,
        client_public_key: String,
    },
    Offer {
        session_id: Uuid,
        target_id: Uuid,
        ticket: String,
        client_public_key: String,
        probe_token: String,
        target_certificate_der: Vec<u8>,
        ticket_public_key_pem: String,
    },
    Candidates {
        session_id: Uuid,
        candidates: Vec<SocketAddr>,
    },
    ProbeSeen {
        session_id: Uuid,
        peer: PeerRole,
        candidate: SocketAddr,
    },
    QuicReady {
        session_id: Uuid,
    },
    SelectRelay {
        session_id: Uuid,
    },
    Activate {
        session_id: Uuid,
        path: SelectedPath,
    },
    Activated {
        session_id: Uuid,
        path: SelectedPath,
    },
    Error {
        session_id: Option<Uuid>,
        code: String,
        message: String,
    },
    Cancel {
        session_id: Uuid,
        reason: String,
    },
}
