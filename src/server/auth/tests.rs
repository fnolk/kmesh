use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use jsonwebtoken::{Algorithm, decode_header};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

use crate::{
    identity,
    protocol::{
        AdminOperation, AdminRequest, AdminResponse, AgentEnrollmentRequest, LoginTokens,
        PasswordLoginRequest, PublicKeyChallengeRequest, PublicKeyLoginRequest, RelayMode,
        TargetPermission,
    },
};

use super::super::{ServerInner, ServerState, admin, control, db::Database};
use super::*;

const TEST_ISSUER: &str = "https://kmesh-auth-contract.test";
const INITIAL_ADMIN_PASSWORD: &str = "initial-admin-password";

struct Fixture {
    state: ServerState,
    data_dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.data_dir);
    }
}

async fn fixture() -> Fixture {
    let data_dir = std::env::temp_dir().join(format!("kmesh-auth-contract-{}", Uuid::new_v4()));
    fs::create_dir_all(&data_dir).expect("create auth-contract test directory");
    let db = Database::open(data_dir.join("server.sqlite3"))
        .await
        .expect("open test database");
    db.apply_schema().await.expect("apply test schema");
    let keys = identity::generate_token_key_set().expect("generate test token keys");
    let admin_hash = password_hash_limited(INITIAL_ADMIN_PASSWORD.to_owned())
        .await
        .expect("hash initial admin password");
    db.initialize(TEST_ISSUER, "admin", Some(admin_hash))
        .await
        .expect("initialize test admin");
    Fixture {
        state: ServerState {
            inner: Arc::new(ServerInner {
                db,
                issuer: TEST_ISSUER.to_owned(),
                keys,
                auth_rate_limiter: AuthRateLimiter::default(),
                online_agents: RwLock::new(HashMap::new()),
                tunnels: RwLock::new(HashMap::new()),
                transport_info: RwLock::new(crate::protocol::TransportInfo {
                    private_relay_url: Some(TEST_ISSUER.to_owned()),
                    qad_port: 3478,
                }),
            }),
        },
        data_dir,
    }
}

fn remote() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51001))
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .expect("build bearer authorization header"),
    );
    headers
}

async fn login(
    state: &ServerState,
    username: &str,
    password: &str,
) -> Result<LoginTokens, ApiError> {
    password_login(
        State(state.clone()),
        remote(),
        Json(PasswordLoginRequest {
            username: username.to_owned(),
            password: password.to_owned(),
        }),
    )
    .await
    .map(|tokens| tokens.0)
}

async fn admin_request(
    state: &ServerState,
    access_token: &str,
    operation: AdminOperation,
) -> Result<AdminResponse, StatusCode> {
    admin::operation(
        State(state.clone()),
        bearer(access_token),
        Json(AdminRequest { operation }),
    )
    .await
    .map(|response| response.0)
    .map_err(|error| error.into_response().status())
}

fn generate_ssh_key(directory: &Path, name: &str, algorithm: &str) -> PathBuf {
    let private_key = directory.join(name);
    let mut command = Command::new("ssh-keygen");
    command
        .args(["-q", "-t", algorithm, "-N", "", "-f"])
        .arg(&private_key);
    if algorithm == "rsa" {
        command.args(["-b", "2048"]);
    } else if algorithm == "ecdsa" {
        command.args(["-b", "256"]);
    }
    let output = command.output().expect("run ssh-keygen for test key");
    assert!(output.status.success(), "ssh-keygen generated the test key");
    private_key
}

fn sshsig(private_key: &Path, payload: &[u8]) -> String {
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(private_key)
        .args(["-n", "kmesh-login"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start ssh-keygen SSHSIG signer");
    child
        .stdin
        .take()
        .expect("open SSHSIG input")
        .write_all(payload)
        .expect("write SSHSIG payload");
    let output = child.wait_with_output().expect("wait for SSHSIG signer");
    assert!(output.status.success(), "ssh-keygen signed test challenge");
    String::from_utf8(output.stdout).expect("SSHSIG output is UTF-8")
}

async fn key_challenge(
    state: &ServerState,
    username: &str,
    public_key: &str,
) -> PublicKeyChallenge {
    public_key_challenge(
        State(state.clone()),
        remote(),
        Json(PublicKeyChallengeRequest {
            username: username.to_owned(),
            public_key: public_key.to_owned(),
        }),
    )
    .await
    .expect("request SSHSIG challenge")
    .0
}

#[tokio::test]
async fn password_and_ssh_sig_contracts_cover_algorithms_expiry_action_and_replay() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let password_tokens = login(state, "ADMIN", INITIAL_ADMIN_PASSWORD)
        .await
        .expect("password login");
    let header = decode_header(&password_tokens.access_token).expect("decode JWT header");
    assert_eq!(header.alg, Algorithm::EdDSA);
    let claims = identity::decode_user_access_token(
        &password_tokens.access_token,
        &state.inner.keys.user_access.public_key_pem,
        TEST_ISSUER,
    )
    .expect("verify Ed25519 access token");
    assert_eq!(claims.exp - claims.iat, 15 * 60);
    assert_eq!(password_tokens.access_expires_at, claims.exp);
    assert_eq!(
        password_tokens.refresh_expires_at - claims.iat,
        30 * 24 * 60 * 60
    );
    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?1")
        .bind(claims.sub.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read stored Argon2 password hash");
    assert!(password_hash.starts_with("$argon2id$"));
    assert_ne!(password_hash, INITIAL_ADMIN_PASSWORD);
    let stored_refresh_hash: String =
        sqlx::query_scalar("SELECT token_hash FROM refresh_tokens WHERE session_id = ?1")
            .bind(claims.sid.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read stored refresh-token hash");
    assert_eq!(
        stored_refresh_hash,
        super::super::hash_secret(&password_tokens.refresh_token)
    );
    assert_ne!(stored_refresh_hash, password_tokens.refresh_token);
    let wrong_password = login(state, "admin", "wrong-password").await;
    assert_eq!(
        wrong_password.unwrap_err().into_response().status(),
        StatusCode::UNAUTHORIZED
    );

    let admin_id = claims.sub;
    for algorithm in ["ed25519", "rsa", "ecdsa"] {
        let private_key =
            generate_ssh_key(&fixture.data_dir, &format!("id_{algorithm}"), algorithm);
        let public_key = fs::read_to_string(private_key.with_extension("pub"))
            .expect("read generated SSH public key");
        admin::apply_operation(
            state,
            admin_id,
            AdminOperation::AddUserKey {
                user_id: admin_id,
                public_key: public_key.clone(),
                label: format!("{algorithm}-test-key"),
            },
        )
        .await
        .expect("register SSHSIG test key");

        let challenge = key_challenge(state, "ADMIN", &public_key).await;
        let now = unix_time() as u64;
        assert!(challenge.expires_at >= now && challenge.expires_at <= now + 60);
        let payload = URL_SAFE_NO_PAD
            .decode(&challenge.challenge)
            .expect("decode SSHSIG payload");
        let request = PublicKeyLoginRequest {
            username: "admin".to_owned(),
            challenge_id: challenge.challenge_id,
            signature: sshsig(&private_key, &payload),
        };
        let logged_in = public_key_login(State(state.clone()), remote(), Json(request.clone()))
            .await
            .expect("OpenSSH SSHSIG login")
            .0;
        let claims = identity::decode_user_access_token(
            &logged_in.access_token,
            &state.inner.keys.user_access.public_key_pem,
            TEST_ISSUER,
        )
        .expect("verify SSHSIG login access token");
        assert_eq!(claims.sub, admin_id);
        let replay = public_key_login(State(state.clone()), remote(), Json(request)).await;
        assert_eq!(
            replay.unwrap_err().into_response().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    let ed25519 = generate_ssh_key(&fixture.data_dir, "id_action_binding", "ed25519");
    let public_key =
        fs::read_to_string(ed25519.with_extension("pub")).expect("read action-binding public key");
    admin::apply_operation(
        state,
        admin_id,
        AdminOperation::AddUserKey {
            user_id: admin_id,
            public_key: public_key.clone(),
            label: "action-binding".to_owned(),
        },
    )
    .await
    .expect("register action-binding key");
    let challenge = key_challenge(state, "admin", &public_key).await;
    let mut altered_payload = URL_SAFE_NO_PAD
        .decode(&challenge.challenge)
        .expect("decode action-bound challenge");
    let action_start = b"kmesh-login-challenge-v1\0".len() + 4;
    assert_eq!(&altered_payload[action_start..action_start + 5], b"login");
    altered_payload[action_start..action_start + 5].copy_from_slice(b"admin");
    let action_changed = public_key_login(
        State(state.clone()),
        remote(),
        Json(PublicKeyLoginRequest {
            username: "admin".to_owned(),
            challenge_id: challenge.challenge_id,
            signature: sshsig(&ed25519, &altered_payload),
        }),
    )
    .await;
    assert_eq!(
        action_changed.unwrap_err().into_response().status(),
        StatusCode::UNAUTHORIZED
    );

    let challenge = key_challenge(state, "admin", &public_key).await;
    let payload = URL_SAFE_NO_PAD
        .decode(&challenge.challenge)
        .expect("decode expiring challenge");
    sqlx::query("UPDATE ssh_login_challenges SET expires_at = ?1 WHERE id = ?2")
        .bind(unix_time() - 1)
        .bind(challenge.challenge_id.to_string())
        .execute(&state.inner.db.pool)
        .await
        .expect("expire test challenge");
    let expired = public_key_login(
        State(state.clone()),
        remote(),
        Json(PublicKeyLoginRequest {
            username: "admin".to_owned(),
            challenge_id: challenge.challenge_id,
            signature: sshsig(&ed25519, &payload),
        }),
    )
    .await;
    assert_eq!(
        expired.unwrap_err().into_response().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn admin_crud_and_ssh_connect_grants_are_separate_authorities() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let admin_tokens = login(state, "admin", INITIAL_ADMIN_PASSWORD)
        .await
        .expect("login administrator");

    let created_user = admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::CreateUser {
            username: "ssh-user".to_owned(),
            password: "ssh-user-initial-password".to_owned(),
        },
    )
    .await
    .expect("create user through admin handler");
    let AdminResponse::User(user) = created_user else {
        panic!("create user returned an unexpected response");
    };
    assert!(matches!(
        admin_request(state, &admin_tokens.access_token, AdminOperation::ListUsers)
            .await
            .expect("list users"),
        AdminResponse::Users(users) if users.iter().any(|candidate| candidate.user_id == user.user_id)
    ));

    let created_role = admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::CreateRole {
            name: "ssh-connect-only".to_owned(),
        },
    )
    .await
    .expect("create SSH-only role");
    let AdminResponse::Role(role) = created_role else {
        panic!("create role returned an unexpected response");
    };
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListRoles,
        )
        .await
        .expect("list roles"),
        AdminResponse::Roles(roles) if roles.iter().any(|candidate| candidate.role_id == role.role_id)
    ));
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::SetUserRoles {
                user_id: user.user_id,
                role_ids: vec![role.role_id, role.role_id],
            },
        )
        .await
        .expect("set user roles"),
        AdminResponse::UserRoles(roles) if roles.len() == 1 && roles[0].role_id == role.role_id
    ));
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListUserRoles { user_id: user.user_id },
        )
        .await
        .expect("list user roles"),
        AdminResponse::UserRoles(roles) if roles.len() == 1 && roles[0].role_id == role.role_id
    ));

    let key_path = generate_ssh_key(&fixture.data_dir, "id_admin_operation", "ed25519");
    let public_key =
        fs::read_to_string(key_path.with_extension("pub")).expect("read admin test public key");
    let added_key = admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::AddUserKey {
            user_id: user.user_id,
            public_key,
            label: "test-key".to_owned(),
        },
    )
    .await
    .expect("add user key");
    let AdminResponse::Keys(keys) = added_key else {
        panic!("add key returned an unexpected response");
    };
    assert_eq!(keys.len(), 1);
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListKeys { user_id: user.user_id },
        )
        .await
        .expect("list user keys"),
        AdminResponse::Keys(listed) if listed.len() == 1 && listed[0].key_id == keys[0].key_id
    ));
    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::RemoveUserKey {
            key_id: keys[0].key_id,
        },
    )
    .await
    .expect("remove user key");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListKeys { user_id: user.user_id },
        )
        .await
        .expect("list keys after removal"),
        AdminResponse::Keys(listed) if listed.is_empty()
    ));

    let created_target = admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::CreateTarget {
            name: "build-machine".to_owned(),
        },
    )
    .await
    .expect("create target");
    let AdminResponse::TargetCreated {
        target,
        enrollment_token,
    } = created_target
    else {
        panic!("create target returned an unexpected response");
    };
    let first_device = iroh::SecretKey::generate();
    let first_enrollment = control::enroll(
        State(state.clone()),
        Json(AgentEnrollmentRequest {
            target_id: target.target_id,
            enrollment_token: enrollment_token.clone(),
            agent_endpoint_id: first_device.public().to_string(),
        }),
    )
    .await
    .expect("enroll target");
    assert_eq!(first_enrollment.0.target_id, target.target_id);
    assert_eq!(
        control::authenticate_agent(state, &bearer(&first_enrollment.0.agent_token))
            .await
            .expect("authenticate first enrollment"),
        target.target_id
    );
    assert_eq!(
        control::enroll(
            State(state.clone()),
            Json(AgentEnrollmentRequest {
                target_id: target.target_id,
                enrollment_token,
                agent_endpoint_id: first_device.public().to_string(),
            }),
        )
        .await
        .unwrap_err()
        .into_response()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let issued = admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::IssueEnrollment {
            target_id: target.target_id,
        },
    )
    .await
    .expect("issue re-enrollment code");
    let AdminResponse::EnrollmentIssued {
        target_id,
        enrollment_token: reenrollment_token,
    } = issued
    else {
        panic!("issue enrollment returned an unexpected response");
    };
    assert_eq!(target_id, target.target_id);
    let second_enrollment = control::enroll(
        State(state.clone()),
        Json(AgentEnrollmentRequest {
            target_id,
            enrollment_token: reenrollment_token,
            agent_endpoint_id: first_device.public().to_string(),
        }),
    )
    .await
    .expect("re-enroll target with a fresh code");
    assert_eq!(second_enrollment.0.target_id, target.target_id);
    assert!(
        control::authenticate_agent(state, &bearer(&first_enrollment.0.agent_token))
            .await
            .is_err(),
        "re-enrollment invalidates the previous agent credential"
    );
    let stored_device_id = state
        .inner
        .db
        .target_endpoint_id(target.target_id)
        .await
        .expect("read stable target device identity");
    let expected_device_id = first_device.public().to_string();
    assert_eq!(
        stored_device_id.as_deref(),
        Some(expected_device_id.as_str())
    );

    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::RenameTarget {
            target_id: target.target_id,
            name: "renamed-machine".to_owned(),
        },
    )
    .await
    .expect("rename target");
    for enabled in [false, true] {
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::SetTargetEnabled {
                target_id: target.target_id,
                enabled,
            },
        )
        .await
        .expect("set target enabled state");
        let target_enabled: i64 = sqlx::query_scalar("SELECT enabled FROM targets WHERE id = ?1")
            .bind(target.target_id.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read target enabled state");
        assert_eq!(target_enabled, i64::from(enabled));
    }

    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::GrantTarget {
            role_id: role.role_id,
            target_id: target.target_id,
            permission: TargetPermission::SshConnect,
        },
    )
    .await
    .expect("grant SSH connect");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListRoleGrants { role_id: role.role_id },
        )
        .await
        .expect("list role grants"),
        AdminResponse::Grants(grants) if grants.len() == 1 && grants[0].target_id == target.target_id
    ));
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListTargets,
        )
        .await
        .expect("list targets"),
        AdminResponse::Targets(targets) if targets.len() == 1 && targets[0].target_id == target.target_id && targets[0].name == "renamed-machine"
    ));

    let (target_sender, mut target_receiver) = mpsc::channel(4);
    let target_connection_id = Uuid::new_v4();
    state.inner.online_agents.write().await.insert(
        target.target_id,
        control::OnlineAgent {
            connection_id: target_connection_id,
            sender: target_sender,
        },
    );
    let admin_user = authenticate(state, &bearer(&admin_tokens.access_token))
        .await
        .expect("authenticate admin");
    let (admin_client_sender, _admin_client_receiver) = mpsc::channel(4);
    assert_eq!(
        control::open_tunnel(
            state,
            admin_user,
            &admin_client_sender,
            Uuid::new_v4(),
            target.target_id,
            iroh::SecretKey::generate().public().to_string(),
            RelayMode::Private,
        )
        .await
        .unwrap_err()
        .into_response()
        .status(),
        StatusCode::FORBIDDEN,
        "the administrator role does not imply SSH connect permission"
    );

    assert_eq!(
        admin_request(
            state,
            &login(state, "ssh-user", "ssh-user-initial-password")
                .await
                .expect("login SSH-only user")
                .access_token,
            AdminOperation::ListUsers,
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN,
        "the ssh_connect grant does not imply administrative authority"
    );
    let user_tokens = login(state, "ssh-user", "ssh-user-initial-password")
        .await
        .expect("login SSH-only user for connection test");
    let visible_targets = admin::targets(State(state.clone()), bearer(&user_tokens.access_token))
        .await
        .expect("list targets visible to SSH-only user")
        .0;
    assert_eq!(visible_targets.len(), 1);
    assert_eq!(visible_targets[0].target_id, target.target_id);
    let user = authenticate(state, &bearer(&user_tokens.access_token))
        .await
        .expect("authenticate SSH-only user");
    let (user_client_sender, _user_client_receiver) = mpsc::channel(4);
    let connected_session = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &user_client_sender,
        connected_session,
        target.target_id,
        iroh::SecretKey::generate().public().to_string(),
        RelayMode::Private,
    )
    .await
    .expect("ssh_connect grant permits a connection");
    assert!(matches!(
        target_receiver.recv().await,
        Some(crate::protocol::ControlMessage::Prepare { session_id, .. })
            if session_id == connected_session
    ));

    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::RevokeTarget {
            role_id: role.role_id,
            target_id: target.target_id,
            permission: TargetPermission::SshConnect,
        },
    )
    .await
    .expect("revoke SSH connect");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListRoleGrants { role_id: role.role_id },
        )
        .await
        .expect("list role grants after revoke"),
        AdminResponse::Grants(grants) if grants.is_empty()
    ));
    let visible_targets = admin::targets(State(state.clone()), bearer(&user_tokens.access_token))
        .await
        .expect("list targets after revoke")
        .0;
    assert!(visible_targets.is_empty());
    let new_session_user = authenticate(state, &bearer(&user_tokens.access_token))
        .await
        .expect("auth session remains valid after grant change");
    assert_eq!(
        control::open_tunnel(
            state,
            new_session_user,
            &user_client_sender,
            Uuid::new_v4(),
            target.target_id,
            iroh::SecretKey::generate().public().to_string(),
            RelayMode::Private,
        )
        .await
        .unwrap_err()
        .into_response()
        .status(),
        StatusCode::FORBIDDEN,
        "the current ssh_connect grant is checked for each new session"
    );
    control::close_pending_client_tunnels(state, &user_client_sender).await;

    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::SetUserEnabled {
            user_id: user.user_id,
            enabled: false,
        },
    )
    .await
    .expect("disable user");
    assert_eq!(
        login(state, "ssh-user", "ssh-user-initial-password")
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED,
        "user disable revokes future login"
    );
    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::SetUserEnabled {
            user_id: user.user_id,
            enabled: true,
        },
    )
    .await
    .expect("re-enable user after disabled-login check");
    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::ResetPassword {
            user_id: user.user_id,
            password: "ssh-user-reset-password".to_owned(),
        },
    )
    .await
    .expect("reset user password");
    login(state, "ssh-user", "ssh-user-reset-password")
        .await
        .expect("login using reset password");
    assert!(
        login(state, "ssh-user", "ssh-user-initial-password")
            .await
            .is_err(),
        "password reset invalidates the old password"
    );

    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::SetUserRoles {
            user_id: user.user_id,
            role_ids: Vec::new(),
        },
    )
    .await
    .expect("clear user roles");
    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::DeleteRole {
            role_id: role.role_id,
        },
    )
    .await
    .expect("delete role");
    admin_request(
        state,
        &admin_tokens.access_token,
        AdminOperation::DeleteTarget {
            target_id: target.target_id,
        },
    )
    .await
    .expect("delete target");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens.access_token,
            AdminOperation::ListTargets,
        )
        .await
        .expect("list targets after deletion"),
        AdminResponse::Targets(targets) if targets.is_empty()
    ));
}
