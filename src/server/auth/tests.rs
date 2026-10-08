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
        AdminOperation, AdminRequest, AdminResponse, AgentEnrollmentRequest, ApiTokenClaims,
        PublicKeyChallengeRequest, PublicKeyLoginRequest, RouteMode, TargetPermission,
    },
};

use super::super::{
    ServerInner, ServerState, admin, control,
    db::{Database, InitialApiToken},
};
use super::*;

const TEST_ISSUER: &str = "https://kmesh-auth-contract.test";
struct Fixture {
    state: ServerState,
    data_dir: PathBuf,
    admin_token: String,
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
    let user_id = "admin".to_owned();
    let token_id = Uuid::new_v4();
    let now = unix_time() as u64;
    let admin_token = identity::encode_api_token(
        &ApiTokenClaims {
            sub: user_id.clone(),
            jti: token_id,
            iss: TEST_ISSUER.to_owned(),
            aud: identity::API_TOKEN_AUDIENCE.to_owned(),
            iat: now,
            exp: None,
        },
        &keys.user_access.private_key_pem,
    )
    .expect("sign initial API token");
    db.initialize(
        TEST_ISSUER,
        "admin",
        Some(InitialApiToken {
            user_id,
            token_id,
            token_hash: super::super::hash_secret(&admin_token),
        }),
    )
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
                relay_clients: RwLock::new(None),
                transport_info: RwLock::new(crate::protocol::TransportInfo {
                    private_relay_url: Some(TEST_ISSUER.to_owned()),
                    qad_port: 3478,
                }),
            }),
        },
        data_dir,
        admin_token,
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

async fn login(state: &ServerState, token: &str) -> Result<String, ApiError> {
    authenticate(state, &bearer(token)).await?;
    Ok(token.to_owned())
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

#[tokio::test]
async fn api_jwt_issue_list_and_revoke_contract() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let admin_token = login(state, &fixture.admin_token)
        .await
        .expect("authenticate initial administrator");
    let admin_id = identity::decode_api_token(
        &admin_token,
        &state.inner.keys.user_access.public_key_pem,
        TEST_ISSUER,
    )
    .expect("decode administrator API JWT")
    .sub;
    let issued = admin_request(
        state,
        &admin_token,
        AdminOperation::CreateApiToken {
            user_id: admin_id.clone(),
            label: "automation".to_owned(),
            expires_in_secs: None,
        },
    )
    .await
    .expect("issue API token");
    let AdminResponse::ApiTokenIssued { api_token, token } = issued else {
        panic!("token issue returned an unexpected response");
    };
    let claims = identity::decode_api_token(
        &token,
        &state.inner.keys.user_access.public_key_pem,
        TEST_ISSUER,
    )
    .expect("verify issued API JWT");
    assert_eq!(claims.sub.clone(), admin_id);
    assert_eq!(claims.jti, api_token.token_id);
    assert_eq!(claims.exp, None);
    assert_eq!(api_token.expires_at, None);
    assert_eq!(decode_header(&token).unwrap().alg, Algorithm::EdDSA);
    let stored_hash: String = sqlx::query_scalar("SELECT token_hash FROM api_tokens WHERE id = ?1")
        .bind(api_token.token_id.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read API token hash");
    assert_eq!(stored_hash, super::super::hash_secret(&token));
    assert_ne!(stored_hash, token);

    assert_eq!(
        admin_request(
            state,
            &admin_token,
            AdminOperation::CreateApiToken {
                user_id: admin_id.clone(),
                label: "zero lifetime".to_owned(),
                expires_in_secs: Some(0),
            },
        )
        .await
        .unwrap_err(),
        StatusCode::BAD_REQUEST
    );

    login(state, &token)
        .await
        .expect("authenticate issued API JWT directly");
    let limited = admin_request(
        state,
        &admin_token,
        AdminOperation::CreateApiToken {
            user_id: admin_id.clone(),
            label: "temporary".to_owned(),
            expires_in_secs: Some(120),
        },
    )
    .await
    .expect("issue limited API JWT");
    let AdminResponse::ApiTokenIssued {
        api_token: limited_view,
        token: limited_token,
    } = limited
    else {
        panic!("limited token issue returned an unexpected response");
    };
    let limited_claims = identity::decode_api_token(
        &limited_token,
        &state.inner.keys.user_access.public_key_pem,
        TEST_ISSUER,
    )
    .expect("verify limited API JWT");
    assert_eq!(
        limited_claims.exp,
        limited_view.expires_at.map(|expires_at| expires_at as u64)
    );
    login(state, &limited_token)
        .await
        .expect("authenticate limited API JWT before expiration");
    let expired_at = unix_time() - 1;
    let expired_id = Uuid::new_v4();
    let expired_token = identity::encode_api_token(
        &ApiTokenClaims {
            sub: admin_id.clone(),
            jti: expired_id,
            iss: TEST_ISSUER.to_owned(),
            aud: identity::API_TOKEN_AUDIENCE.to_owned(),
            iat: (expired_at - 60) as u64,
            exp: Some(expired_at as u64),
        },
        &state.inner.keys.user_access.private_key_pem,
    )
    .expect("sign expired API JWT");
    sqlx::query(
        "INSERT INTO api_tokens(id, user_id, token_hash, label, created_at, expires_at) \
         VALUES (?1, ?2, ?3, 'expired', ?4, ?5)",
    )
    .bind(expired_id.to_string())
    .bind(admin_id.to_string())
    .bind(super::super::hash_secret(&expired_token))
    .bind(expired_at - 120)
    .bind(expired_at)
    .execute(&state.inner.db.pool)
    .await
    .expect("register expired API JWT");
    assert!(
        identity::decode_api_token(
            &expired_token,
            &state.inner.keys.user_access.public_key_pem,
            TEST_ISSUER,
        )
        .is_err()
    );
    assert_eq!(
        authenticate(state, &bearer(&expired_token))
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED,
        "an expired JWT is rejected without leeway"
    );
    let listed = admin_request(
        state,
        &admin_token,
        AdminOperation::ListApiTokens { user_id: admin_id },
    )
    .await
    .expect("list API tokens");
    assert!(matches!(
        listed,
        AdminResponse::ApiTokens(tokens)
            if tokens.iter().any(|listed| listed.token_id == api_token.token_id
                && listed.label == "automation"
                && listed.expires_at.is_none()
                && listed.revoked_at.is_none())
    ));

    admin_request(
        state,
        &admin_token,
        AdminOperation::RevokeApiToken {
            token_id: api_token.token_id,
        },
    )
    .await
    .expect("revoke API token");
    assert!(authenticate(state, &bearer(&token)).await.is_err());
    assert_eq!(
        login(state, &token)
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED
    );
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
async fn api_token_and_ssh_sig_contracts_cover_algorithms_expiry_action_and_replay() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let api_token = login(state, &fixture.admin_token)
        .await
        .expect("authenticate API JWT");
    let header = decode_header(&api_token).expect("decode JWT header");
    assert_eq!(header.alg, Algorithm::EdDSA);
    let claims = identity::decode_api_token(
        &api_token,
        &state.inner.keys.user_access.public_key_pem,
        TEST_ISSUER,
    )
    .expect("verify Ed25519 API JWT");
    assert_eq!(claims.aud, identity::API_TOKEN_AUDIENCE);
    assert_eq!(claims.exp, None);
    assert!(
        identity::decode_user_access_token(
            &api_token,
            &state.inner.keys.user_access.public_key_pem,
            TEST_ISSUER,
        )
        .is_err()
    );
    let access_token = identity::encode_user_access_token(
        &crate::protocol::AccessTokenClaims {
            sub: claims.sub.clone(),
            sid: Uuid::new_v4(),
            iss: TEST_ISSUER.to_owned(),
            aud: identity::USER_TOKEN_AUDIENCE.to_owned(),
            iat: unix_time() as u64,
            exp: (unix_time() + 60) as u64,
        },
        &state.inner.keys.user_access.private_key_pem,
    )
    .expect("sign public-key session access JWT");
    assert!(
        identity::decode_api_token(
            &access_token,
            &state.inner.keys.user_access.public_key_pem,
            TEST_ISSUER,
        )
        .is_err()
    );
    let stored_api_token_hash: String =
        sqlx::query_scalar("SELECT token_hash FROM api_tokens WHERE user_id = ?1")
            .bind(claims.sub.clone().to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read stored API token hash");
    assert_eq!(stored_api_token_hash, super::super::hash_secret(&api_token));
    assert_ne!(stored_api_token_hash, fixture.admin_token);
    let wrong_token = login(state, "invalid-api-token").await;
    assert_eq!(
        wrong_token.unwrap_err().into_response().status(),
        StatusCode::UNAUTHORIZED
    );

    let admin_id = claims.sub.clone();
    for algorithm in ["ed25519", "rsa", "ecdsa"] {
        let private_key =
            generate_ssh_key(&fixture.data_dir, &format!("id_{algorithm}"), algorithm);
        let public_key = fs::read_to_string(private_key.with_extension("pub"))
            .expect("read generated SSH public key");
        admin::apply_operation(
            state,
            admin_id.clone(),
            AdminOperation::AddUserKey {
                user_id: admin_id.clone(),
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
        assert_eq!(claims.sub.clone(), admin_id);
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
        admin_id.clone(),
        AdminOperation::AddUserKey {
            user_id: admin_id.clone(),
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
    let admin_tokens = login(state, &fixture.admin_token)
        .await
        .expect("login administrator");

    let created_user = admin_request(
        state,
        &admin_tokens,
        AdminOperation::CreateUser {
            username: " SSH-User ".to_owned(),
        },
    )
    .await
    .expect("create user through admin handler");
    let AdminResponse::User(user) = created_user else {
        panic!("create user returned an unexpected response");
    };
    assert_eq!(user.user_id, "ssh-user");
    assert_eq!(user.username, "ssh-user");
    assert_eq!(user.system_role, crate::protocol::SystemRole::Member);
    assert_eq!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::CreateUser {
                username: "SSH-USER".to_owned(),
            },
        )
        .await
        .unwrap_err(),
        StatusCode::CONFLICT
    );
    let user_token = match admin_request(
        state,
        &admin_tokens,
        AdminOperation::CreateApiToken {
            user_id: user.user_id.clone(),
            label: "ssh-user test".to_owned(),
            expires_in_secs: None,
        },
    )
    .await
    .expect("issue SSH-only user API token")
    {
        AdminResponse::ApiTokenIssued { token, .. } => token,
        _ => panic!("API token creation returned an unexpected response"),
    };
    assert_eq!(
        identity::decode_api_token(
            &user_token,
            &state.inner.keys.user_access.public_key_pem,
            TEST_ISSUER,
        )
        .expect("verify SSH-only user's API JWT")
        .sub,
        user.user_id
    );
    assert!(matches!(
        admin_request(state, &admin_tokens, AdminOperation::ListUsers)
            .await
            .expect("list users"),
        AdminResponse::Users(users) if users.iter().any(|candidate| candidate.user_id == user.user_id.clone())
    ));

    let created_access_group = admin_request(
        state,
        &admin_tokens,
        AdminOperation::CreateAccessGroup {
            name: "SSH-Connect-Only".to_owned(),
        },
    )
    .await
    .expect("create SSH-only access_group");
    let AdminResponse::AccessGroup(access_group) = created_access_group else {
        panic!("create access_group returned an unexpected response");
    };
    assert_eq!(access_group.group_id, "ssh-connect-only");
    assert_eq!(access_group.name, "SSH-Connect-Only");
    assert_eq!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::CreateAccessGroup {
                name: "ssh-connect-only".to_owned(),
            },
        )
        .await
        .unwrap_err(),
        StatusCode::CONFLICT
    );
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListGroups,
        )
        .await
        .expect("list access_groups"),
        AdminResponse::AccessGroups(access_groups) if access_groups.iter().any(|candidate| candidate.group_id == access_group.group_id.clone())
    ));
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::SetUserAccessGroups {
                user_id: user.user_id.clone(),
                group_ids: vec![access_group.group_id.clone(), access_group.group_id.clone()],
            },
        )
        .await
        .expect("set user access_groups"),
        AdminResponse::UserAccessGroups(access_groups) if access_groups.len() == 1 && access_groups[0].group_id == access_group.group_id.clone()
    ));

    let identity = admin::me(State(state.clone()), bearer(&user_token))
        .await
        .expect("read member identity")
        .0;
    assert_eq!(identity.system_role, crate::protocol::SystemRole::Member);
    assert_eq!(identity.access_groups[0].group_id, access_group.group_id);
    assert_eq!(
        admin_request(state, &user_token, AdminOperation::ListUsers)
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN,
        "access group membership does not grant platform administration"
    );
    admin_request(
        state,
        &admin_tokens,
        AdminOperation::SetUserSystemRole {
            user_id: user.user_id.clone(),
            system_role: crate::protocol::SystemRole::Admin,
        },
    )
    .await
    .expect("promote user to a platform admin");
    assert!(matches!(
        admin_request(state, &user_token, AdminOperation::ListUsers)
            .await
            .expect("old token uses current system role"),
        AdminResponse::Users(_)
    ));
    admin_request(
        state,
        &admin_tokens,
        AdminOperation::SetUserSystemRole {
            user_id: user.user_id.clone(),
            system_role: crate::protocol::SystemRole::Member,
        },
    )
    .await
    .expect("demote user to a platform member");
    assert_eq!(
        admin_request(state, &user_token, AdminOperation::ListUsers)
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN,
        "the same token uses the current member role after demotion"
    );
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListUserAccessGroups {
                user_id: user.user_id.clone(),
            },
        )
        .await
        .expect("system role changes leave access groups unchanged"),
        AdminResponse::UserAccessGroups(groups)
            if groups.len() == 1 && groups[0].group_id == access_group.group_id
    ));
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListUserAccessGroups { user_id: user.user_id.clone() },
        )
        .await
        .expect("list user access_groups"),
        AdminResponse::UserAccessGroups(access_groups) if access_groups.len() == 1 && access_groups[0].group_id == access_group.group_id.clone()
    ));

    let key_path = generate_ssh_key(&fixture.data_dir, "id_admin_operation", "ed25519");
    let public_key =
        fs::read_to_string(key_path.with_extension("pub")).expect("read admin test public key");
    let added_key = admin_request(
        state,
        &admin_tokens,
        AdminOperation::AddUserKey {
            user_id: user.user_id.clone(),
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
            &admin_tokens,
            AdminOperation::ListKeys { user_id: user.user_id.clone() },
        )
        .await
        .expect("list user keys"),
        AdminResponse::Keys(listed) if listed.len() == 1 && listed[0].key_id == keys[0].key_id
    ));
    admin_request(
        state,
        &admin_tokens,
        AdminOperation::RemoveUserKey {
            key_id: keys[0].key_id,
        },
    )
    .await
    .expect("remove user key");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListKeys { user_id: user.user_id.clone() },
        )
        .await
        .expect("list keys after removal"),
        AdminResponse::Keys(listed) if listed.is_empty()
    ));

    let created_target = admin_request(
        state,
        &admin_tokens,
        AdminOperation::CreateTarget {
            name: "Build-Machine".to_owned(),
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
    assert_eq!(target.target_id, "build-machine");
    assert_eq!(target.name, "Build-Machine");
    assert_eq!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::CreateTarget {
                name: "BUILD-MACHINE".to_owned(),
            },
        )
        .await
        .unwrap_err(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::CreateTarget {
                name: "not/a-slug".to_owned(),
            },
        )
        .await
        .unwrap_err(),
        StatusCode::BAD_REQUEST
    );
    let first_device = iroh::SecretKey::generate();
    let first_enrollment = control::enroll(
        State(state.clone()),
        Json(AgentEnrollmentRequest {
            target_id: target.target_id.clone(),
            enrollment_token: enrollment_token.clone(),
            agent_endpoint_id: first_device.public().to_string(),
        }),
    )
    .await
    .expect("enroll target");
    assert_eq!(first_enrollment.0.target_id, target.target_id.clone());
    assert_eq!(
        control::authenticate_agent(state, &bearer(&first_enrollment.0.agent_token))
            .await
            .expect("authenticate first enrollment"),
        target.target_id.clone()
    );
    assert_eq!(
        control::enroll(
            State(state.clone()),
            Json(AgentEnrollmentRequest {
                target_id: target.target_id.clone(),
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
        &admin_tokens,
        AdminOperation::IssueEnrollment {
            target_id: target.target_id.clone(),
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
    assert_eq!(target_id, target.target_id.clone());
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
    assert_eq!(second_enrollment.0.target_id, target.target_id.clone());
    assert!(
        control::authenticate_agent(state, &bearer(&first_enrollment.0.agent_token))
            .await
            .is_err(),
        "re-enrollment invalidates the previous agent credential"
    );
    let stored_device_id = state
        .inner
        .db
        .target_endpoint_id(&target.target_id.clone())
        .await
        .expect("read stable target device identity");
    let expected_device_id = first_device.public().to_string();
    assert_eq!(
        stored_device_id.as_deref(),
        Some(expected_device_id.as_str())
    );

    admin_request(
        state,
        &admin_tokens,
        AdminOperation::RenameTarget {
            target_id: target.target_id.clone(),
            name: "Renamed-Machine".to_owned(),
        },
    )
    .await
    .expect("rename target");
    for enabled in [false, true] {
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::SetTargetEnabled {
                target_id: target.target_id.clone(),
                enabled,
            },
        )
        .await
        .expect("set target enabled state");
        let target_enabled: i64 = sqlx::query_scalar("SELECT enabled FROM targets WHERE id = ?1")
            .bind(target.target_id.clone().to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read target enabled state");
        assert_eq!(target_enabled, i64::from(enabled));
    }

    admin_request(
        state,
        &admin_tokens,
        AdminOperation::GrantTarget {
            group_id: access_group.group_id.clone(),
            target_id: target.target_id.clone(),
            permission: TargetPermission::SshConnect,
        },
    )
    .await
    .expect("grant SSH connect");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListGroupGrants { group_id: access_group.group_id.clone() },
        )
        .await
        .expect("list access_group grants"),
        AdminResponse::Grants(grants) if grants.len() == 1 && grants[0].target_id == target.target_id.clone()
    ));
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListTargets,
        )
        .await
        .expect("list targets"),
        AdminResponse::Targets(targets) if targets.len() == 1 && targets[0].target_id == target.target_id.clone() && targets[0].name == "Renamed-Machine"
    ));

    let (target_sender, mut target_receiver) = mpsc::channel(4);
    let target_connection_id = Uuid::new_v4();
    state.inner.online_agents.write().await.insert(
        target.target_id.clone(),
        control::OnlineAgent {
            connection_id: target_connection_id,
            sender: target_sender,
        },
    );
    let admin_user = authenticate(state, &bearer(&admin_tokens))
        .await
        .expect("authenticate admin");
    let (admin_client_sender, _admin_client_receiver) = mpsc::channel(4);
    assert_eq!(
        control::open_tunnel(
            state,
            admin_user,
            &admin_client_sender,
            Uuid::new_v4(),
            &target.target_id.clone(),
            iroh::SecretKey::generate().public().to_string(),
            RouteMode::PrivateRelay,
        )
        .await
        .unwrap_err()
        .into_response()
        .status(),
        StatusCode::FORBIDDEN,
        "the admin role does not grant SSH access by itself"
    );

    admin_request(
        state,
        &admin_tokens,
        AdminOperation::SetUserAccessGroups {
            user_id: "admin".to_owned(),
            group_ids: vec![access_group.group_id.clone()],
        },
    )
    .await
    .expect("add admin to the granted access group");
    let admin_user = authenticate(state, &bearer(&admin_tokens))
        .await
        .expect("authenticate admin after group assignment");
    let admin_session = Uuid::new_v4();
    control::open_tunnel(
        state,
        admin_user,
        &admin_client_sender,
        admin_session,
        &target.target_id,
        iroh::SecretKey::generate().public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("admin needs and uses the access group grant for SSH");
    assert!(matches!(
        target_receiver.recv().await,
        Some(crate::protocol::ControlMessage::Prepare { session_id, .. })
            if session_id == admin_session
    ));
    control::close_pending_client_tunnels(state, &admin_client_sender).await;
    assert!(matches!(
        target_receiver.recv().await,
        Some(crate::protocol::ControlMessage::Close { session_id, .. })
            if session_id == admin_session
    ));

    assert_eq!(
        admin_request(
            state,
            &login(state, &user_token)
                .await
                .expect("login SSH-only user")
                .to_owned(),
            AdminOperation::ListUsers,
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN,
        "the ssh_connect grant does not imply administrative authority"
    );
    let user_tokens = login(state, &user_token)
        .await
        .expect("login SSH-only user for connection test");
    let visible_targets = admin::targets(State(state.clone()), bearer(&user_tokens))
        .await
        .expect("list targets visible to SSH-only user")
        .0;
    assert_eq!(visible_targets.len(), 1);
    assert_eq!(visible_targets[0].target_id, target.target_id.clone());
    let user = authenticate(state, &bearer(&user_tokens))
        .await
        .expect("authenticate SSH-only user");
    let (user_client_sender, _user_client_receiver) = mpsc::channel(4);
    let connected_session = Uuid::new_v4();
    control::open_tunnel(
        state,
        user.clone(),
        &user_client_sender,
        connected_session,
        &target.target_id.clone(),
        iroh::SecretKey::generate().public().to_string(),
        RouteMode::PrivateRelay,
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
        &admin_tokens,
        AdminOperation::RevokeTarget {
            group_id: access_group.group_id.clone(),
            target_id: target.target_id.clone(),
            permission: TargetPermission::SshConnect,
        },
    )
    .await
    .expect("revoke SSH connect");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListGroupGrants { group_id: access_group.group_id.clone() },
        )
        .await
        .expect("list access_group grants after revoke"),
        AdminResponse::Grants(grants) if grants.is_empty()
    ));
    let visible_targets = admin::targets(State(state.clone()), bearer(&user_tokens))
        .await
        .expect("list targets after revoke")
        .0;
    assert!(visible_targets.is_empty());
    let new_session_user = authenticate(state, &bearer(&user_tokens))
        .await
        .expect("auth session remains valid after grant change");
    assert_eq!(
        control::open_tunnel(
            state,
            new_session_user,
            &user_client_sender,
            Uuid::new_v4(),
            &target.target_id.clone(),
            iroh::SecretKey::generate().public().to_string(),
            RouteMode::PrivateRelay,
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
        &admin_tokens,
        AdminOperation::SetUserEnabled {
            user_id: user.user_id.clone(),
            enabled: false,
        },
    )
    .await
    .expect("disable user");
    assert_eq!(
        login(state, &user_token)
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED,
        "user disable revokes future login"
    );
    admin_request(
        state,
        &admin_tokens,
        AdminOperation::SetUserEnabled {
            user_id: user.user_id.clone(),
            enabled: true,
        },
    )
    .await
    .expect("re-enable user after disabled-login check");
    login(state, &user_token)
        .await
        .expect("login with the user's API token after re-enable");

    admin_request(
        state,
        &admin_tokens,
        AdminOperation::SetUserAccessGroups {
            user_id: user.user_id.clone(),
            group_ids: Vec::new(),
        },
    )
    .await
    .expect("clear user access_groups");
    admin_request(
        state,
        &admin_tokens,
        AdminOperation::DeleteAccessGroup {
            group_id: access_group.group_id.clone(),
        },
    )
    .await
    .expect("delete access_group");
    admin_request(
        state,
        &admin_tokens,
        AdminOperation::DeleteTarget {
            target_id: target.target_id.clone(),
        },
    )
    .await
    .expect("delete target");
    assert!(matches!(
        admin_request(
            state,
            &admin_tokens,
            AdminOperation::ListTargets,
        )
        .await
        .expect("list targets after deletion"),
        AdminResponse::Targets(targets) if targets.is_empty()
    ));
}

#[tokio::test]
async fn member_with_admin_named_access_group_is_not_an_admin() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let admin_token = login(state, &fixture.admin_token)
        .await
        .expect("login initial admin");
    let initial_admin = admin::me(State(state.clone()), bearer(&admin_token))
        .await
        .expect("read initial admin identity")
        .0;
    assert_eq!(
        initial_admin.system_role,
        crate::protocol::SystemRole::Admin
    );
    assert!(initial_admin.access_groups.is_empty());
    assert!(matches!(
        admin_request(state, &admin_token, AdminOperation::ListUsers)
            .await
            .expect("admin access remains after an empty group list"),
        AdminResponse::Users(_)
    ));

    let member = match admin_request(
        state,
        &admin_token,
        AdminOperation::CreateUser {
            username: "ordinary".to_owned(),
        },
    )
    .await
    .expect("create member")
    {
        AdminResponse::User(user) => user,
        _ => panic!("create user returned an unexpected response"),
    };
    assert_eq!(member.system_role, crate::protocol::SystemRole::Member);
    let member_token = match admin_request(
        state,
        &admin_token,
        AdminOperation::CreateApiToken {
            user_id: member.user_id.clone(),
            label: "member token".to_owned(),
            expires_in_secs: None,
        },
    )
    .await
    .expect("issue member token")
    {
        AdminResponse::ApiTokenIssued { token, .. } => token,
        _ => panic!("token creation returned an unexpected response"),
    };
    let admin_named_group = match admin_request(
        state,
        &admin_token,
        AdminOperation::CreateAccessGroup {
            name: "admin".to_owned(),
        },
    )
    .await
    .expect("create an access group named admin")
    {
        AdminResponse::AccessGroup(group) => group,
        _ => panic!("group creation returned an unexpected response"),
    };
    admin_request(
        state,
        &admin_token,
        AdminOperation::SetUserAccessGroups {
            user_id: member.user_id.clone(),
            group_ids: vec![admin_named_group.group_id.clone()],
        },
    )
    .await
    .expect("add member to the admin-named access group");
    let identity = admin::me(State(state.clone()), bearer(&member_token))
        .await
        .expect("read member identity")
        .0;
    assert_eq!(identity.system_role, crate::protocol::SystemRole::Member);
    assert_eq!(identity.access_groups[0].group_id, "admin");
    assert_eq!(
        admin_request(state, &member_token, AdminOperation::ListUsers)
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    admin_request(
        state,
        &admin_token,
        AdminOperation::SetUserAccessGroups {
            user_id: member.user_id.clone(),
            group_ids: Vec::new(),
        },
    )
    .await
    .expect("remove all member access groups");
    let identity = admin::me(State(state.clone()), bearer(&member_token))
        .await
        .expect("read member identity after group removal")
        .0;
    assert_eq!(identity.system_role, crate::protocol::SystemRole::Member);
    assert!(identity.access_groups.is_empty());
    assert_eq!(
        admin_request(state, &member_token, AdminOperation::ListUsers)
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn every_admin_operation_rejects_a_member() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let admin_token = &fixture.admin_token;
    let member = match admin_request(
        state,
        admin_token,
        AdminOperation::CreateUser {
            username: "member".to_owned(),
        },
    )
    .await
    .expect("create member")
    {
        AdminResponse::User(user) => user,
        _ => panic!("create user returned an unexpected response"),
    };
    let member_token = match admin_request(
        state,
        admin_token,
        AdminOperation::CreateApiToken {
            user_id: member.user_id.clone(),
            label: "member".to_owned(),
            expires_in_secs: None,
        },
    )
    .await
    .expect("issue member token")
    {
        AdminResponse::ApiTokenIssued { token, .. } => token,
        _ => panic!("token creation returned an unexpected response"),
    };
    let operations = [
        AdminOperation::ListUsers,
        AdminOperation::ListRelayTraffic,
        AdminOperation::CloseRelaySession {
            session_id: Uuid::new_v4(),
        },
        AdminOperation::CreateUser {
            username: "blocked".to_owned(),
        },
        AdminOperation::SetUserEnabled {
            user_id: member.user_id.clone(),
            enabled: false,
        },
        AdminOperation::CreateApiToken {
            user_id: member.user_id.clone(),
            label: "blocked".to_owned(),
            expires_in_secs: None,
        },
        AdminOperation::ListApiTokens {
            user_id: member.user_id.clone(),
        },
        AdminOperation::RevokeApiToken {
            token_id: Uuid::new_v4(),
        },
        AdminOperation::AddUserKey {
            user_id: member.user_id.clone(),
            public_key: "invalid".to_owned(),
            label: String::new(),
        },
        AdminOperation::RemoveUserKey {
            key_id: Uuid::new_v4(),
        },
        AdminOperation::ListKeys {
            user_id: member.user_id.clone(),
        },
        AdminOperation::ListRoles,
        AdminOperation::SetUserSystemRole {
            user_id: member.user_id.clone(),
            system_role: crate::protocol::SystemRole::Admin,
        },
        AdminOperation::ListGroups,
        AdminOperation::CreateAccessGroup {
            name: "blocked".to_owned(),
        },
        AdminOperation::DeleteAccessGroup {
            group_id: "blocked".to_owned(),
        },
        AdminOperation::SetUserAccessGroups {
            user_id: member.user_id.clone(),
            group_ids: Vec::new(),
        },
        AdminOperation::ListUserAccessGroups {
            user_id: member.user_id.clone(),
        },
        AdminOperation::GrantTarget {
            group_id: "blocked".to_owned(),
            target_id: "blocked".to_owned(),
            permission: TargetPermission::SshConnect,
        },
        AdminOperation::RevokeTarget {
            group_id: "blocked".to_owned(),
            target_id: "blocked".to_owned(),
            permission: TargetPermission::SshConnect,
        },
        AdminOperation::ListGroupGrants {
            group_id: "blocked".to_owned(),
        },
        AdminOperation::ListTargets,
        AdminOperation::CreateTarget {
            name: "blocked".to_owned(),
        },
        AdminOperation::RenameTarget {
            target_id: "blocked".to_owned(),
            name: "renamed".to_owned(),
        },
        AdminOperation::SetTargetEnabled {
            target_id: "blocked".to_owned(),
            enabled: false,
        },
        AdminOperation::DeleteTarget {
            target_id: "blocked".to_owned(),
        },
        AdminOperation::IssueEnrollment {
            target_id: "blocked".to_owned(),
        },
    ];
    for operation in operations {
        assert_eq!(
            admin_request(state, &member_token, operation)
                .await
                .unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(state.inner.db.user_count().await.expect("count users"), 2);
}

#[tokio::test]
async fn concurrent_role_changes_keep_one_enabled_admin() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let admin_token = &fixture.admin_token;
    let second_admin = match admin_request(
        state,
        admin_token,
        AdminOperation::CreateUser {
            username: "second-admin".to_owned(),
        },
    )
    .await
    .expect("create second user")
    {
        AdminResponse::User(user) => user,
        _ => panic!("create user returned an unexpected response"),
    };
    let second_token = match admin_request(
        state,
        admin_token,
        AdminOperation::CreateApiToken {
            user_id: second_admin.user_id.clone(),
            label: "second admin".to_owned(),
            expires_in_secs: None,
        },
    )
    .await
    .expect("issue second admin token")
    {
        AdminResponse::ApiTokenIssued { token, .. } => token,
        _ => panic!("token creation returned an unexpected response"),
    };
    admin_request(
        state,
        admin_token,
        AdminOperation::SetUserSystemRole {
            user_id: second_admin.user_id.clone(),
            system_role: crate::protocol::SystemRole::Admin,
        },
    )
    .await
    .expect("promote second user");

    let (first, second) = tokio::join!(
        admin_request(
            state,
            admin_token,
            AdminOperation::SetUserSystemRole {
                user_id: "admin".to_owned(),
                system_role: crate::protocol::SystemRole::Member,
            },
        ),
        admin_request(
            state,
            &second_token,
            AdminOperation::SetUserSystemRole {
                user_id: second_admin.user_id.clone(),
                system_role: crate::protocol::SystemRole::Member,
            },
        ),
    );
    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|status| matches!(*status, StatusCode::FORBIDDEN | StatusCode::CONFLICT))
    );
    let admin_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE enabled = 1 AND system_role = 'admin'",
    )
    .fetch_one(&state.inner.db.pool)
    .await
    .expect("count enabled admins");
    assert_eq!(admin_count, 1);
}
