use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use axum::{
    Json,
    extract::{ConnectInfo, State},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use iroh::Watcher as _;
use iroh::{EndpointAddr, RelayUrl, SecretKey};
use iroh_relay::{
    http::ProtocolVersion,
    server::{Access, AccessControl, ClientRequest},
};
use rcgen::generate_simple_self_signed;
use sqlx::Row;
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{RwLock, mpsc},
    time::timeout,
};
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, http::HeaderValue as WsHeaderValue,
};
use uuid::Uuid;

use crate::{
    config::TlsConfig,
    identity,
    protocol::{
        AdminOperation, AdminResponse, AgentEnrollmentRequest, ControlMessage, LoginTokens,
        PasswordLoginRequest, PublicKeyChallengeRequest, PublicKeyLoginRequest, RefreshRequest,
        RelayMode, TargetPermission, TunnelTicketClaims,
    },
    transport::{
        IrohByteStream, IrohEndpointOptions, RelayChoice, accept_peer, connect_peer,
        create_endpoint, http_client,
    },
};

use super::{
    PersistedKeys, ServerInner, ServerState, auth,
    control::{self, OnlineAgent},
    db::Database,
};

struct Fixture {
    state: ServerState,
    data_dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

async fn fixture(issuer: &str) -> Fixture {
    let data_dir = std::env::temp_dir().join(format!("kmesh-server-test-{}", Uuid::new_v4()));
    super::initialize(&data_dir, "Admin", "initial-admin-password", issuer)
        .await
        .expect("initialize test server");
    let key_bytes = std::fs::read(data_dir.join("token-keys.json")).expect("read generated keys");
    let db = Database::open(data_dir.join("server.sqlite3"))
        .await
        .expect("open test DB");
    db.apply_schema().await.expect("apply test schema");
    let keys = PersistedKeys::from_slice(&key_bytes)
        .expect("decode generated keys")
        .into_token_keys();
    Fixture {
        state: ServerState {
            inner: Arc::new(ServerInner {
                db,
                issuer: issuer.to_owned(),
                keys,
                auth_rate_limiter: auth::AuthRateLimiter::default(),
                online_agents: RwLock::new(std::collections::HashMap::new()),
                tunnels: RwLock::new(std::collections::HashMap::new()),
                transport_info: RwLock::new(crate::protocol::TransportInfo {
                    private_relay_url: Some(issuer.to_owned()),
                    qad_port: 3478,
                }),
            }),
        },
        data_dir,
    }
}

fn remote() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50001))
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("build bearer header"),
    );
    headers
}

async fn login_password(state: &ServerState) -> LoginTokens {
    auth::password_login(
        State(state.clone()),
        remote(),
        Json(PasswordLoginRequest {
            username: "ADMIN".to_owned(),
            password: "initial-admin-password".to_owned(),
        }),
    )
    .await
    .expect("password login")
    .0
}

async fn admin_role_id(state: &ServerState) -> Uuid {
    sqlx::query_scalar::<_, String>("SELECT id FROM roles WHERE name = 'admin'")
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read admin role")
        .parse()
        .expect("parse admin role ID")
}

async fn admin_user_id(state: &ServerState) -> Uuid {
    sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE username = 'admin'")
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read initial admin")
        .parse()
        .expect("parse admin user ID")
}

async fn create_enrolled_target(
    state: &ServerState,
    name: &str,
    endpoint_secret_key: &SecretKey,
) -> (Uuid, String) {
    let created = super::admin::apply_operation(
        state,
        admin_user_id(state).await,
        AdminOperation::CreateTarget {
            name: name.to_owned(),
        },
    )
    .await
    .expect("create target");
    let AdminResponse::TargetCreated {
        target,
        enrollment_token,
    } = created
    else {
        panic!("target creation returned an unexpected result");
    };
    let enrolled = control::enroll(
        State(state.clone()),
        Json(AgentEnrollmentRequest {
            target_id: target.target_id,
            enrollment_token: enrollment_token.clone(),
            agent_endpoint_id: endpoint_secret_key.public().to_string(),
        }),
    )
    .await
    .expect("enroll target Iroh endpoint")
    .0;
    assert_eq!(enrolled.target_id, target.target_id);
    assert_eq!(
        enrolled.ticket_public_key_pem,
        state.inner.keys.tunnel_ticket.public_key_pem
    );
    let stored_hash =
        sqlx::query_scalar::<_, String>("SELECT agent_token_hash FROM targets WHERE id = ?1")
            .bind(target.target_id.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read stored agent token hash");
    assert_eq!(stored_hash, super::hash_secret(&enrolled.agent_token));
    assert_ne!(stored_hash, enrolled.agent_token);
    let replay = control::enroll(
        State(state.clone()),
        Json(AgentEnrollmentRequest {
            target_id: target.target_id,
            enrollment_token,
            agent_endpoint_id: endpoint_secret_key.public().to_string(),
        }),
    )
    .await;
    assert!(replay.is_err(), "enrollment token must be one-time");
    (target.target_id, enrolled.agent_token)
}

async fn grant_target(state: &ServerState, target_id: Uuid) {
    let role_id = admin_role_id(state).await;
    super::admin::apply_operation(
        state,
        admin_user_id(state).await,
        AdminOperation::GrantTarget {
            role_id,
            target_id,
            permission: TargetPermission::SshConnect,
        },
    )
    .await
    .expect("grant target access");
}

async fn revoke_target(state: &ServerState, target_id: Uuid) {
    let role_id = admin_role_id(state).await;
    super::admin::apply_operation(
        state,
        admin_user_id(state).await,
        AdminOperation::RevokeTarget {
            role_id,
            target_id,
            permission: TargetPermission::SshConnect,
        },
    )
    .await
    .expect("revoke target access");
}

async fn online_target(
    state: &ServerState,
    target_id: Uuid,
    endpoint_secret_key: &SecretKey,
) -> (Uuid, mpsc::Receiver<ControlMessage>) {
    let connection_id = Uuid::new_v4();
    let (sender, receiver) = mpsc::channel(64);
    let relay_url: RelayUrl = reqwest::Url::parse(&state.inner.issuer)
        .expect("valid test issuer")
        .into();
    state.inner.online_agents.write().await.insert(
        target_id,
        OnlineAgent {
            connection_id,
            sender,
            endpoints: std::collections::HashMap::from([(
                RelayMode::Private,
                EndpointAddr::new(endpoint_secret_key.public()).with_relay_url(relay_url),
            )]),
        },
    );
    (connection_id, receiver)
}

fn endpoint_connect_request(endpoint_id: iroh::EndpointId) -> ClientRequest {
    let request = hyper::Request::builder()
        .uri("https://kmesh.test/relay")
        .body(())
        .expect("build relay request");
    let (parts, _) = request.into_parts();
    ClientRequest::new(endpoint_id, ProtocolVersion::V2, parts)
}

#[tokio::test]
async fn schema_v2_requires_a_fresh_data_directory() {
    let data_dir = std::env::temp_dir().join(format!("kmesh-schema-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&data_dir).expect("create schema test directory");
    let db = Database::open(data_dir.join("server.sqlite3"))
        .await
        .expect("open schema test database");
    sqlx::query(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)",
    )
    .execute(&db.pool)
    .await
    .expect("create previous schema marker");
    sqlx::query("INSERT INTO schema_migrations(version, applied_at) VALUES (2, 0)")
        .execute(&db.pool)
        .await
        .expect("record previous schema version");

    let error = db
        .apply_schema()
        .await
        .expect_err("schema version 2 must fail before applying schema 3");
    assert!(
        error
            .to_string()
            .contains("requires a fresh data directory")
    );

    db.pool.close().await;
    std::fs::remove_dir_all(data_dir).expect("remove schema test directory");
}

#[tokio::test]
async fn admin_audit_commits_with_mutations_and_failed_audit_rolls_back() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let actor_id = admin_user_id(state).await;

    sqlx::query(
        "CREATE TRIGGER reject_admin_audit BEFORE INSERT ON admin_audit \
         BEGIN SELECT RAISE(ABORT, 'test audit insert failure'); END",
    )
    .execute(&state.inner.db.pool)
    .await
    .expect("install audit failure trigger");
    let result = super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::CreateTarget {
            name: "rolled-back-target".to_owned(),
        },
    )
    .await;
    assert!(result.is_err(), "audit failure must fail the operation");
    let target_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM targets WHERE name = 'rolled-back-target'",
    )
    .fetch_one(&state.inner.db.pool)
    .await
    .expect("read rolled-back target count");
    assert_eq!(
        target_count, 0,
        "the target mutation shares the audit transaction"
    );

    sqlx::query("DROP TRIGGER reject_admin_audit")
        .execute(&state.inner.db.pool)
        .await
        .expect("remove audit failure trigger");
    let result = super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::RenameTarget {
            target_id: Uuid::new_v4(),
            name: "missing-target".to_owned(),
        },
    )
    .await;
    assert!(result.is_err(), "a missing target operation must fail");
    let audit_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM admin_audit")
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read audit count after failures");
    assert_eq!(audit_count, 0, "failed operations leave no success record");

    let created = super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::CreateTarget {
            name: "audited-target".to_owned(),
        },
    )
    .await
    .expect("create target with audit");
    let AdminResponse::TargetCreated { target, .. } = created else {
        panic!("target creation returned an unexpected result");
    };
    let row = sqlx::query(
        "SELECT actor_user_id, operation, object_type, object_id, context_json \
         FROM admin_audit WHERE operation = 'create_target'",
    )
    .fetch_one(&state.inner.db.pool)
    .await
    .expect("read target creation audit");
    assert_eq!(
        row.try_get::<String, _>("actor_user_id").unwrap(),
        actor_id.to_string()
    );
    assert_eq!(
        row.try_get::<String, _>("operation").unwrap(),
        "create_target"
    );
    assert_eq!(row.try_get::<String, _>("object_type").unwrap(), "target");
    assert_eq!(
        row.try_get::<String, _>("object_id").unwrap(),
        target.target_id.to_string()
    );
    let context: serde_json::Value =
        serde_json::from_str(&row.try_get::<String, _>("context_json").unwrap())
            .expect("decode audit context");
    assert_eq!(context["name"], "audited-target");
}

#[tokio::test]
async fn admin_audit_redacts_secrets_and_preserves_deleted_role_relations() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let actor_id = admin_user_id(state).await;
    let password = "audit-user-password-secret";
    let created_user = super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::CreateUser {
            username: "audit-user".to_owned(),
            password: password.to_owned(),
        },
    )
    .await
    .expect("create audited user");
    let AdminResponse::User(user) = created_user else {
        panic!("user creation returned an unexpected result");
    };

    let created_target = super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::CreateTarget {
            name: "audit-target".to_owned(),
        },
    )
    .await
    .expect("create audited target");
    let AdminResponse::TargetCreated {
        target,
        enrollment_token,
    } = created_target
    else {
        panic!("target creation returned an unexpected result");
    };

    let private = PrivateKey::from_openssh(TEST_PRIVATE_KEY).expect("parse test SSH key");
    let public_key = private
        .public_key()
        .to_openssh()
        .expect("encode test public key")
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::AddUserKey {
            user_id: user.user_id,
            public_key: public_key.clone(),
            label: "audit-test-key".to_owned(),
        },
    )
    .await
    .expect("register audited SSH key");
    super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::ResetPassword {
            user_id: user.user_id,
            password: "replacement-password-secret".to_owned(),
        },
    )
    .await
    .expect("reset password");

    let created_role = super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::CreateRole {
            name: "audit-role".to_owned(),
        },
    )
    .await
    .expect("create audited role");
    let AdminResponse::Role(role) = created_role else {
        panic!("role creation returned an unexpected result");
    };
    super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::SetUserRoles {
            user_id: user.user_id,
            role_ids: vec![role.role_id, role.role_id],
        },
    )
    .await
    .expect("assign audited role");
    super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::GrantTarget {
            role_id: role.role_id,
            target_id: target.target_id,
            permission: TargetPermission::SshConnect,
        },
    )
    .await
    .expect("grant audited target");
    super::admin::apply_operation(
        state,
        actor_id,
        AdminOperation::DeleteRole {
            role_id: role.role_id,
        },
    )
    .await
    .expect("delete audited role");

    let audit_rows = sqlx::query(
        "SELECT operation, object_id, context_json FROM admin_audit ORDER BY occurred_at, id",
    )
    .fetch_all(&state.inner.db.pool)
    .await
    .expect("read admin audit rows");
    let contexts = audit_rows
        .iter()
        .map(|row| row.try_get::<String, _>("context_json").unwrap())
        .collect::<Vec<_>>();
    let audit_dump = contexts.join("\n");
    let password_hash =
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = ?1")
            .bind(user.user_id.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read stored password hash");
    assert!(!audit_dump.contains(password));
    assert!(!audit_dump.contains("replacement-password-secret"));
    assert!(!audit_dump.contains(&password_hash));
    assert!(!audit_dump.contains(&enrollment_token));
    assert!(!audit_dump.contains(&public_key));

    let delete_row = audit_rows
        .iter()
        .find(|row| row.try_get::<String, _>("operation").unwrap() == "delete_role")
        .expect("deleted role audit row");
    assert_eq!(
        delete_row.try_get::<String, _>("object_id").unwrap(),
        role.role_id.to_string()
    );
    let context: serde_json::Value =
        serde_json::from_str(&delete_row.try_get::<String, _>("context_json").unwrap())
            .expect("decode deleted role context");
    assert_eq!(context["role_name"], "audit-role");
    assert_eq!(context["user_ids"][0], user.user_id.to_string());
    assert_eq!(
        context["grants"][0]["target_id"],
        target.target_id.to_string()
    );
    assert_eq!(context["grants"][0]["permission"], "ssh_connect");

    let role_exists =
        sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM roles WHERE id = ?1)")
            .bind(role.role_id.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("verify role deletion");
    assert_eq!(role_exists, 0);
}

#[tokio::test]
async fn relay_access_denies_unknown_endpoint_and_allows_registered_target() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let unknown = SecretKey::generate().public();
    assert!(matches!(
        state.on_connect(&endpoint_connect_request(unknown)).await,
        Access::Deny { .. }
    ));

    let target_secret = SecretKey::generate();
    let (target_id, agent_token) =
        create_enrolled_target(state, "relay-target", &target_secret).await;
    assert_eq!(
        control::authenticate_agent(state, &bearer(&agent_token))
            .await
            .expect("authenticate enrolled target"),
        target_id
    );
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(target_secret.public()))
            .await,
        Access::Allow
    );
}

#[tokio::test]
async fn pending_endpoint_access_is_revoked_before_activation_and_active_session_survives_rbac_change()
 {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let target_secret = SecretKey::generate();
    let (target_id, _) = create_enrolled_target(state, "activation-target", &target_secret).await;
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) =
        online_target(state, target_id, &target_secret).await;
    let (client_sender, mut client_receiver) = mpsc::channel(64);

    let denied_client_key = SecretKey::generate();
    let denied_session_id = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        denied_session_id,
        target_id,
        denied_client_key.public().to_string(),
        RelayMode::Private,
    )
    .await
    .expect("open pending SSH session");
    assert!(matches!(
        target_receiver.recv().await.expect("target preparation"),
        ControlMessage::Prepare { session_id: id, relay_mode: RelayMode::Private } if id == denied_session_id
    ));
    control::send_target_offer(
        state,
        target_id,
        target_connection_id,
        RelayMode::Private,
        denied_session_id,
    )
    .await;
    let ControlMessage::Offer { ticket, .. } = target_receiver.recv().await.expect("target offer")
    else {
        panic!("target received another control message");
    };
    let claims: TunnelTicketClaims = identity::decode_tunnel_ticket(
        &ticket,
        &state.inner.keys.tunnel_ticket.public_key_pem,
        &state.inner.issuer,
    )
    .expect("decode signed ticket");
    assert_eq!(
        claims.client_endpoint_id,
        denied_client_key.public().to_string()
    );
    assert_eq!(
        claims.target_endpoint_id,
        target_secret.public().to_string()
    );
    control::send_offer_to_client(
        state,
        target_id,
        target_connection_id,
        RelayMode::Private,
        denied_session_id,
    )
    .await;
    let _ = client_receiver.recv().await.expect("client offer");
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(denied_client_key.public()))
            .await,
        Access::Allow
    );
    revoke_target(state, target_id).await;
    control::activate_tunnel(
        state,
        target_id,
        target_connection_id,
        denied_session_id,
        denied_client_key.public().to_string(),
        RelayMode::Private,
    )
    .await;
    let denied_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(denied_session_id.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read denied pending status");
    assert_eq!(denied_status, "closed");
    assert!(matches!(
        client_receiver.recv().await.expect("activation denial to client"),
        ControlMessage::Error { session_id: Some(id), .. } if id == denied_session_id
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("activation denial to target"),
        ControlMessage::Error { session_id: Some(id), .. } if id == denied_session_id
    ));
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(denied_client_key.public()))
            .await,
        Access::Deny { .. }
    ));

    grant_target(state, target_id).await;
    let active_client_key = SecretKey::generate();
    let active_session_id = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        active_session_id,
        target_id,
        active_client_key.public().to_string(),
        RelayMode::Private,
    )
    .await
    .expect("open second pending SSH session");
    assert!(matches!(
        target_receiver.recv().await.expect("second target preparation"),
        ControlMessage::Prepare { session_id: id, relay_mode: RelayMode::Private } if id == active_session_id
    ));
    control::send_target_offer(
        state,
        target_id,
        target_connection_id,
        RelayMode::Private,
        active_session_id,
    )
    .await;
    let _ = target_receiver.recv().await.expect("second target offer");
    control::send_offer_to_client(
        state,
        target_id,
        target_connection_id,
        RelayMode::Private,
        active_session_id,
    )
    .await;
    let _ = client_receiver.recv().await.expect("second client offer");
    control::activate_tunnel(
        state,
        target_id,
        target_connection_id,
        active_session_id,
        active_client_key.public().to_string(),
        RelayMode::Private,
    )
    .await;
    let active_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(active_session_id.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read active session status");
    assert_eq!(active_status, "active");
    revoke_target(state, target_id).await;
    auth::logout(State(state.clone()), bearer(&login.access_token))
        .await
        .expect("logout");
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(active_client_key.public()))
            .await,
        Access::Allow
    );
    let retained: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(active_session_id.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read retained session");
    assert_eq!(retained, "active");
}

#[tokio::test]
async fn public_default_mode_works_without_a_private_relay() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    state.inner.transport_info.write().await.private_relay_url = None;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let target_secret = SecretKey::generate();
    let (target_id, _) = create_enrolled_target(state, "public-mode-target", &target_secret).await;
    grant_target(state, target_id).await;

    let relay_url = crate::transport::allowed_relay_urls(&RelayChoice::PublicDefault)
        .expect("load SDK default relay allowlist")
        .into_iter()
        .next()
        .expect("SDK default relay set is nonempty");
    let public_endpoint_addr = EndpointAddr::new(target_secret.public()).with_relay_url(relay_url);
    let target_connection_id = Uuid::new_v4();
    let (target_sender, mut target_receiver) = mpsc::channel(16);
    state.inner.online_agents.write().await.insert(
        target_id,
        OnlineAgent {
            connection_id: target_connection_id,
            sender: target_sender,
            endpoints: std::collections::HashMap::new(),
        },
    );
    let (client_sender, mut client_receiver) = mpsc::channel(16);
    let client_secret = SecretKey::generate();
    let session_id = Uuid::new_v4();

    assert!(
        control::open_tunnel(
            state,
            user,
            &client_sender,
            Uuid::new_v4(),
            target_id,
            client_secret.public().to_string(),
            RelayMode::Private,
        )
        .await
        .is_err()
    );
    control::open_tunnel(
        state,
        user,
        &client_sender,
        session_id,
        target_id,
        client_secret.public().to_string(),
        RelayMode::PublicDefault,
    )
    .await
    .expect("public mode remains available without a private relay");
    assert!(matches!(
        target_receiver.recv().await.expect("target preparation"),
        ControlMessage::Prepare { session_id: received, relay_mode: RelayMode::PublicDefault }
            if received == session_id
    ));
    control::handle_agent_message(
        state,
        target_id,
        target_connection_id,
        ControlMessage::AgentReady {
            session_id: Some(session_id),
            relay_mode: RelayMode::PublicDefault,
            endpoint_addr: public_endpoint_addr,
        },
    )
    .await;
    let ControlMessage::Offer { ticket, .. } = target_receiver.recv().await.expect("target offer")
    else {
        panic!("target received another control message");
    };
    let claims: TunnelTicketClaims = identity::decode_tunnel_ticket(
        &ticket,
        &state.inner.keys.tunnel_ticket.public_key_pem,
        &state.inner.issuer,
    )
    .expect("decode public-mode ticket");
    assert_eq!(claims.relay_mode, RelayMode::PublicDefault);
    control::handle_agent_message(
        state,
        target_id,
        target_connection_id,
        ControlMessage::OfferReady {
            session_id,
            relay_mode: RelayMode::PublicDefault,
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("client offer"),
        ControlMessage::Offer { session_id: received, relay_mode: RelayMode::PublicDefault, .. }
            if received == session_id
    ));
}

#[tokio::test]
async fn sshsig_comment_canonicalization_and_challenge_replay() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let private = PrivateKey::from_openssh(TEST_PRIVATE_KEY).expect("parse test SSH key");
    let with_comment = format!(
        "{} temporary-comment",
        private
            .public_key()
            .to_openssh()
            .expect("encode test public key")
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    );
    let no_comment = with_comment
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        auth::canonical_ssh_key(&with_comment).expect("canonical key with comment"),
        auth::canonical_ssh_key(&no_comment).expect("canonical key without comment")
    );
    let admin_id = admin_user_id(state).await;
    super::admin::apply_operation(
        state,
        admin_id,
        AdminOperation::AddUserKey {
            user_id: admin_id,
            public_key: with_comment.clone(),
            label: "test-key".to_owned(),
        },
    )
    .await
    .expect("register SSH key");
    let challenge = auth::public_key_challenge(
        State(state.clone()),
        remote(),
        Json(PublicKeyChallengeRequest {
            username: "ADMIN".to_owned(),
            public_key: with_comment,
        }),
    )
    .await
    .expect("get SSHSIG challenge")
    .0;
    let payload = URL_SAFE_NO_PAD
        .decode(challenge.challenge.as_bytes())
        .expect("decode signed challenge payload");
    let signature = private
        .sign("kmesh-login", HashAlg::Sha512, &payload)
        .expect("sign challenge");
    let request = PublicKeyLoginRequest {
        username: "admin".to_owned(),
        challenge_id: challenge.challenge_id,
        signature: signature.to_pem(LineEnding::LF).expect("encode SSHSIG"),
    };
    let _tokens = auth::public_key_login(State(state.clone()), remote(), Json(request.clone()))
        .await
        .expect("first SSHSIG login");
    assert!(
        auth::public_key_login(State(state.clone()), remote(), Json(request))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rotated_refresh_replay_revokes_the_session() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let tokens = login_password(state).await;
    let request = RefreshRequest {
        refresh_token: tokens.refresh_token,
    };
    let peer = remote();
    let (first, second) = tokio::join!(
        auth::refresh(State(state.clone()), peer, Json(request.clone())),
        auth::refresh(State(state.clone()), peer, Json(request)),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let tokens = first
        .or(second)
        .expect("one request initially rotates the token")
        .0;
    assert!(
        auth::authenticate(state, &bearer(&tokens.access_token))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn self_hosted_https_relay_qad_and_activated_ssh_stream_work_together() {
    let port_probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve HTTPS test port");
    let https_port = port_probe.local_addr().expect("read test port").port();
    drop(port_probe);
    let issuer = format!("https://localhost:{https_port}");
    let fixture = fixture(&issuer).await;
    let state = &fixture.state;

    let server_cert = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate local relay certificate");
    let cert_path = fixture.data_dir.join("relay-cert.pem");
    let key_path = fixture.data_dir.join("relay-key.pem");
    std::fs::write(&cert_path, server_cert.cert.pem()).expect("write local relay certificate");
    std::fs::write(&key_path, server_cert.signing_key.serialize_pem())
        .expect("write local relay key");
    let tls = TlsConfig {
        ca_certificates: vec![cert_path.clone()],
        ..TlsConfig::default()
    };

    let relay_server = super::iroh::listen_and_serve(
        super::router(state.clone()),
        Some(Arc::new(state.clone())),
        SocketAddr::from(([127, 0, 0, 1], https_port)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &cert_path,
        &key_path,
    )
    .await
    .expect("start local HTTPS relay and QAD");
    state.inner.transport_info.write().await.qad_port = relay_server.qad_addr().port();

    let http = http_client(&tls).expect("build TLS-verified HTTP client");
    let ping = http
        .get(format!("{issuer}/ping"))
        .send()
        .await
        .expect("probe local Iroh relay");
    assert_eq!(ping.status(), reqwest::StatusCode::OK);
    let health = http
        .get(format!("{issuer}/health"))
        .send()
        .await
        .expect("probe kmesh HTTP API");
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let published_transport: crate::protocol::TransportInfo = http
        .get(format!("{issuer}/v1/transport"))
        .send()
        .await
        .expect("read private transport settings")
        .json()
        .await
        .expect("decode private transport settings");
    assert_eq!(
        published_transport.private_relay_url.as_deref(),
        Some(issuer.as_str())
    );
    assert_eq!(published_transport.qad_port, relay_server.qad_addr().port());

    let target_secret = SecretKey::generate();
    let (target_id, agent_token) =
        create_enrolled_target(state, "self-hosted-target", &target_secret).await;
    grant_target(state, target_id).await;
    let relay_url: RelayUrl = reqwest::Url::parse(&issuer)
        .expect("parse private relay URL")
        .into();
    let relay_choice = RelayChoice::Private {
        url: reqwest::Url::parse(&issuer).expect("parse private relay URL"),
        qad_port: relay_server.qad_addr().port(),
    };
    let endpoint_options = IrohEndpointOptions {
        relay_choice: relay_choice.clone(),
        tls: tls.clone(),
    };
    let target_endpoint = create_endpoint(target_secret.clone(), true, endpoint_options.clone())
        .await
        .expect("create target endpoint");
    timeout(Duration::from_secs(15), target_endpoint.online())
        .await
        .expect("target did not connect to the private relay");
    let report = timeout(
        Duration::from_secs(15),
        target_endpoint.net_report().initialized(),
    )
    .await
    .expect("target QAD network report timed out");
    assert!(
        report.udp_v4,
        "target QAD did not complete an IPv4 round trip"
    );
    assert!(
        report.global_v4.is_some(),
        "target QAD did not report its observed IPv4 address"
    );
    assert_eq!(report.preferred_relay.as_ref(), Some(&relay_url));

    let mut agent_control = connect_control_ws(&issuer, "agent/control", &agent_token, &tls).await;
    let relay_only_target_addr = EndpointAddr::new(target_endpoint.id()).with_relay_url(relay_url);
    send_control(
        &mut agent_control,
        &ControlMessage::AgentReady {
            session_id: None,
            relay_mode: RelayMode::Private,
            endpoint_addr: relay_only_target_addr.clone(),
        },
    )
    .await;
    timeout(Duration::from_secs(5), async {
        loop {
            let ready = state
                .inner
                .online_agents
                .read()
                .await
                .get(&target_id)
                .is_some_and(|agent| agent.endpoints.contains_key(&RelayMode::Private));
            if ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not register target endpoint address");

    let login = login_password(state).await;
    let mut client_control =
        connect_control_ws(&issuer, "connect", &login.access_token, &tls).await;
    let client_secret = SecretKey::generate();
    let session_id = Uuid::new_v4();
    send_control(
        &mut client_control,
        &ControlMessage::Open {
            session_id,
            target_id,
            client_endpoint_id: client_secret.public().to_string(),
            relay_mode: RelayMode::Private,
        },
    )
    .await;
    assert!(matches!(
        timeout(Duration::from_secs(10), receive_control(&mut agent_control))
            .await
            .expect("timed out waiting for target prepare"),
        ControlMessage::Prepare { session_id: received, relay_mode: RelayMode::Private } if received == session_id
    ));
    let client_accept = {
        let endpoint = target_endpoint.clone();
        tokio::spawn(async move { accept_peer(&endpoint).await })
    };
    send_control(
        &mut agent_control,
        &ControlMessage::AgentReady {
            session_id: Some(session_id),
            relay_mode: RelayMode::Private,
            endpoint_addr: relay_only_target_addr.clone(),
        },
    )
    .await;
    let ControlMessage::Offer {
        session_id: target_offer_id,
        ticket,
        target_endpoint_addr,
        ticket_public_key_pem,
        relay_mode: RelayMode::Private,
        ..
    } = timeout(Duration::from_secs(10), receive_control(&mut agent_control))
        .await
        .expect("timed out waiting for target offer")
    else {
        panic!("target received a non-offer control message");
    };
    assert_eq!(target_offer_id, session_id);
    assert_eq!(target_endpoint_addr, relay_only_target_addr);
    send_control(
        &mut agent_control,
        &ControlMessage::OfferReady {
            session_id,
            relay_mode: RelayMode::Private,
        },
    )
    .await;
    let ControlMessage::Offer {
        session_id: client_offer_id,
        ticket: client_ticket,
        client_endpoint_id,
        target_endpoint_addr: client_target_addr,
        relay_mode: RelayMode::Private,
        ..
    } = timeout(
        Duration::from_secs(10),
        receive_control(&mut client_control),
    )
    .await
    .expect("timed out waiting for client offer")
    else {
        panic!("client received a non-offer control message");
    };
    assert_eq!(client_offer_id, session_id);
    assert_eq!(client_ticket, ticket);
    assert_eq!(client_target_addr, relay_only_target_addr);
    let claims: TunnelTicketClaims =
        identity::decode_tunnel_ticket(&ticket, &ticket_public_key_pem, &issuer)
            .expect("verify server ticket");
    assert_eq!(claims.client_endpoint_id, client_endpoint_id);
    assert_eq!(claims.target_endpoint_id, target_endpoint.id().to_string());

    let client_endpoint = create_endpoint(client_secret, false, endpoint_options)
        .await
        .expect("create SSH client Iroh endpoint");
    timeout(Duration::from_secs(15), client_endpoint.online())
        .await
        .expect("client did not connect to the private relay");
    let connection = timeout(
        Duration::from_secs(15),
        connect_peer(&client_endpoint, client_target_addr, &relay_choice),
    )
    .await
    .expect("Iroh peer connection timed out")
    .expect("connect through the self-hosted relay");
    let mut client_stream = IrohByteStream::open_bi(connection)
        .await
        .expect("open client SSH stream");
    client_stream
        .write_u32(ticket.len() as u32)
        .await
        .expect("write ticket frame length");
    client_stream
        .write_all(ticket.as_bytes())
        .await
        .expect("write signed ticket");

    let accepted = timeout(Duration::from_secs(15), client_accept)
        .await
        .expect("target did not accept client endpoint")
        .expect("target accept task panicked")
        .expect("accept Iroh peer");
    let mut target_stream = IrohByteStream::accept_bi(accepted)
        .await
        .expect("accept SSH stream");
    let received_ticket_size = target_stream
        .read_u32()
        .await
        .expect("read target ticket length") as usize;
    let mut received_ticket = vec![0; received_ticket_size];
    target_stream
        .read_exact(&mut received_ticket)
        .await
        .expect("read target ticket");
    assert_eq!(received_ticket, ticket.as_bytes());
    assert_eq!(
        target_stream.connection().remote_id().to_string(),
        client_endpoint_id
    );
    send_control(
        &mut agent_control,
        &ControlMessage::IrohReady {
            session_id,
            client_endpoint_id,
            relay_mode: RelayMode::Private,
        },
    )
    .await;
    assert!(matches!(
        timeout(Duration::from_secs(10), receive_control(&mut client_control))
            .await
            .expect("client activation timed out"),
        ControlMessage::Activated { session_id: received } if received == session_id
    ));
    assert!(matches!(
        timeout(Duration::from_secs(10), receive_control(&mut agent_control))
            .await
            .expect("target activation timed out"),
        ControlMessage::Activated { session_id: received } if received == session_id
    ));

    let ssh_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock sshd");
    let ssh_addr = ssh_listener.local_addr().expect("read mock sshd address");
    let echo_task = tokio::spawn(async move {
        let (mut ssh, _) = ssh_listener.accept().await.expect("accept mock ssh client");
        let mut buffer = [0; 4096];
        loop {
            let count = ssh.read(&mut buffer).await.expect("read mock SSH bytes");
            if count == 0 {
                break;
            }
            ssh.write_all(&buffer[..count])
                .await
                .expect("echo mock SSH bytes");
        }
        ssh.shutdown().await.expect("close mock SSH output");
    });
    let target_bridge = tokio::spawn(async move {
        let mut ssh = TcpStream::connect(ssh_addr)
            .await
            .expect("connect mock sshd");
        let copied = tokio::io::copy_bidirectional(&mut ssh, &mut target_stream)
            .await
            .expect("bridge mock SSH and Iroh");
        target_stream
            .finish_send_and_wait()
            .await
            .expect("target waits for final SSH bytes acknowledgement");
        target_stream.connection().close(
            iroh::endpoint::VarInt::from_u32(0),
            b"self-hosted test complete",
        );
        copied
    });
    let payload = b"kmesh ssh bytes through self-hosted iroh relay";
    client_stream
        .write_all(payload)
        .await
        .expect("write SSH test payload");
    client_stream
        .shutdown()
        .await
        .expect("half-close client SSH input");
    let mut echoed = vec![0; payload.len()];
    timeout(
        Duration::from_secs(10),
        client_stream.read_exact(&mut echoed),
    )
    .await
    .expect("SSH echo timed out")
    .expect("read SSH echo");
    assert_eq!(echoed, payload);
    let mut trailing = Vec::new();
    timeout(
        Duration::from_secs(10),
        client_stream.read_to_end(&mut trailing),
    )
    .await
    .expect("SSH close timed out")
    .expect("read final SSH EOF");
    assert!(trailing.is_empty());
    client_stream
        .finish_send_and_wait()
        .await
        .expect("client waits for final SSH bytes acknowledgement");
    client_stream.connection().close(
        iroh::endpoint::VarInt::from_u32(0),
        b"self-hosted test complete",
    );
    timeout(Duration::from_secs(10), target_bridge)
        .await
        .expect("target bridge timed out")
        .expect("target bridge panicked");
    timeout(Duration::from_secs(10), echo_task)
        .await
        .expect("mock sshd timed out")
        .expect("mock sshd panicked");

    send_control(
        &mut client_control,
        &ControlMessage::Close {
            session_id,
            reason: "self_hosted_test_complete".to_owned(),
        },
    )
    .await;
    timeout(Duration::from_secs(10), async {
        loop {
            let status: String =
                sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
                    .bind(session_id.to_string())
                    .fetch_one(&state.inner.db.pool)
                    .await
                    .expect("read completed session status");
            if status == "closed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not close completed session");
    assert!(
        state
            .on_connect(&endpoint_connect_request(
                claims.client_endpoint_id.parse().unwrap()
            ))
            .await
            .eq(&Access::Deny {
                reason: Some("EndpointId is not registered for kmesh".to_owned())
            })
    );

    client_endpoint.close().await;
    target_endpoint.close().await;
    relay_server
        .shutdown()
        .await
        .expect("stop local relay and QAD");
}

async fn connect_control_ws(
    issuer: &str,
    path: &str,
    token: &str,
    tls: &TlsConfig,
) -> crate::transport::WsStream {
    let mut url =
        reqwest::Url::parse(&format!("{issuer}/v1/{path}")).expect("build local control URL");
    url.set_scheme("wss").expect("switch control URL to WSS");
    let mut request = url
        .as_str()
        .into_client_request()
        .expect("build WSS request");
    request.headers_mut().insert(
        AUTHORIZATION,
        WsHeaderValue::from_str(&format!("Bearer {token}")).expect("build WSS bearer header"),
    );
    crate::transport::connect_wss(request, tls)
        .await
        .expect("connect TLS-verified WSS control channel")
}

async fn send_control(websocket: &mut crate::transport::WsStream, message: &ControlMessage) {
    websocket
        .send(Message::Text(
            serde_json::to_string(message)
                .expect("encode test control message")
                .into(),
        ))
        .await
        .expect("send test control message");
}

async fn receive_control(websocket: &mut crate::transport::WsStream) -> ControlMessage {
    loop {
        match websocket
            .next()
            .await
            .expect("test control websocket closed")
            .expect("read test control websocket")
        {
            Message::Text(text) => {
                return serde_json::from_str(&text).expect("decode test control message");
            }
            Message::Binary(bytes) => {
                return serde_json::from_slice(&bytes).expect("decode test control message");
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) | Message::Frame(_) => panic!("test control websocket closed"),
        }
    }
}

const TEST_PRIVATE_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----"#;
