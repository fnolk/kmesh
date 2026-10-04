mod route_acceptance;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
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
        AdminOperation, AdminResponse, AgentEnrollmentRequest, ControlMessage, DiscoveryResult,
        LoginTokens, NativePlan, PasswordLoginRequest, PublicKeyChallengeRequest,
        PublicKeyLoginRequest, ReadyDiscovery, RefreshRequest, RouteMode, SelectedPath,
        TargetPermission, TunnelTicketClaims,
    },
    transport::{
        IrohByteStream, IrohEndpointOptions, QadObservation, QadReflector, RelayChoice,
        accept_peer, connect_peer, create_endpoint, http_client, wait_for_selected_path,
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
) -> (Uuid, mpsc::Receiver<ControlMessage>) {
    let connection_id = Uuid::new_v4();
    let (sender, receiver) = mpsc::channel(64);
    state.inner.online_agents.write().await.insert(
        target_id,
        OnlineAgent {
            connection_id,
            sender,
        },
    );
    (connection_id, receiver)
}

async fn send_agent_ready_for_session(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    route_mode: RouteMode,
    stable_device_key: &SecretKey,
    target_receiver: &mut mpsc::Receiver<ControlMessage>,
) -> SecretKey {
    let runtime = state
        .inner
        .tunnels
        .read()
        .await
        .get(&session_id)
        .cloned()
        .expect("session is registered");
    let data_key = SecretKey::generate();
    let signature = stable_device_key
        .sign(&identity::agent_session_identity_payload(
            session_id,
            target_id,
            route_mode,
            &data_key.public(),
            runtime.expires_at,
        ))
        .to_bytes()
        .to_vec();
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::AgentIdentity {
            session_id,
            route_mode,
            target_data_endpoint_id: data_key.public().to_string(),
            signature,
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("agent identity accepted"),
        ControlMessage::IdentityAccepted { session_id: id, route_mode: mode }
            if id == session_id && mode == route_mode
    ));
    if route_mode == RouteMode::PrivateRelay {
        assert!(matches!(
            target_receiver.recv().await.expect("private relay native plan"),
            ControlMessage::ContinueNative {
                session_id: id,
                route_mode: mode,
                plan: NativePlan::Standard,
            } if id == session_id && mode == route_mode
        ));
    } else {
        control::handle_agent_message(
            state,
            target_id,
            connection_id,
            ControlMessage::CandidatesReady {
                session_id,
                route_mode,
                discovery: DiscoveryResult::Unavailable {
                    reason: "test selects native transport".to_owned(),
                },
            },
        )
        .await;
        assert!(matches!(
            target_receiver.recv().await.expect("native transport plan"),
            ControlMessage::ContinueNative {
                session_id: id,
                route_mode: mode,
                plan: NativePlan::Standard,
            } if id == session_id && mode == route_mode
        ));
    }
    let endpoint_addr = match route_mode {
        RouteMode::PrivateRelay => EndpointAddr::new(data_key.public()).with_relay_url(
            reqwest::Url::parse(&state.inner.issuer)
                .expect("valid test issuer")
                .into(),
        ),
        RouteMode::PrivateDirect | RouteMode::PublicDirect => EndpointAddr::new(data_key.public())
            .with_ip_addr(SocketAddr::from(([203, 0, 113, 10], 41000))),
    };
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::AgentReady {
            session_id,
            route_mode,
            endpoint_addr,
        },
    )
    .await;
    data_key
}

async fn exchange_test_client_candidates(
    state: &ServerState,
    client_receiver: &mut mpsc::Receiver<ControlMessage>,
    target_receiver: &mut mpsc::Receiver<ControlMessage>,
    session_id: Uuid,
    client_secret: &SecretKey,
    route_mode: RouteMode,
    relay_url: RelayUrl,
) -> (ControlMessage, ControlMessage, String) {
    let runtime = state
        .inner
        .tunnels
        .read()
        .await
        .get(&session_id)
        .cloned()
        .expect("session is registered");
    let user = super::auth::AuthenticatedUser {
        user_id: runtime.user_id,
        session_id: runtime.auth_session_id,
        access_expires_at: runtime.access_expires_at,
    };
    let client_sender = runtime.client_sender.clone();
    let target_id = runtime.target_id;
    let client_offer = client_receiver
        .recv()
        .await
        .expect("client receives candidate offer");
    let ControlMessage::ClientOffer {
        session_id: offered_session,
        target_id: offered_target,
        client_endpoint_id,
        target_endpoint_id,
        route_mode: offered_mode,
        ..
    } = &client_offer
    else {
        panic!("client receives another control message instead of ClientOffer");
    };
    assert_eq!(*offered_session, session_id);
    assert_eq!(*offered_target, target_id);
    assert_eq!(client_endpoint_id, &client_secret.public().to_string());
    assert_eq!(*offered_mode, route_mode);
    let target_data_endpoint_id = target_endpoint_id.clone();
    let enrolled_endpoint_id = state
        .inner
        .db
        .target_endpoint_id(target_id)
        .await
        .expect("read enrolled target EndpointId")
        .expect("target is enrolled");
    assert_ne!(target_endpoint_id, &enrolled_endpoint_id);

    let client_endpoint_addr = match route_mode {
        RouteMode::PrivateRelay => {
            EndpointAddr::new(client_secret.public()).with_relay_url(relay_url.clone())
        }
        RouteMode::PrivateDirect | RouteMode::PublicDirect => {
            EndpointAddr::new(client_secret.public())
                .with_ip_addr(SocketAddr::from(([198, 51, 100, 20], 32000)))
        }
    };
    assert!(matches!(
        client_receiver.recv().await.expect("client native plan"),
        ControlMessage::ContinueNative {
            session_id: id,
            route_mode: mode,
            plan: NativePlan::Standard,
        } if id == session_id && mode == route_mode
    ));
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::ClientReady {
            session_id,
            route_mode,
            client_endpoint_addr: client_endpoint_addr.clone(),
        },
    )
    .await;
    let dial_offer = target_receiver
        .recv()
        .await
        .expect("target receives dial offer");
    let ControlMessage::DialOffer {
        session_id: dial_session,
        target_id: dial_target,
        client_endpoint_id: dial_client_id,
        client_endpoint_addr: dial_client_addr,
        route_mode: dial_mode,
        ..
    } = &dial_offer
    else {
        panic!("target receives another control message instead of DialOffer");
    };
    assert_eq!(*dial_session, session_id);
    assert_eq!(*dial_target, target_id);
    assert_eq!(dial_client_id, &client_secret.public().to_string());
    assert_eq!(dial_client_addr, &client_endpoint_addr);
    assert_eq!(*dial_mode, route_mode);
    let (client_path, target_path) = match route_mode {
        RouteMode::PrivateRelay => {
            let url = relay_url.as_str().to_owned();
            (
                SelectedPath::PrivateRelay { url: url.clone() },
                SelectedPath::PrivateRelay { url },
            )
        }
        RouteMode::PrivateDirect | RouteMode::PublicDirect => (
            SelectedPath::Direct {
                remote_address: SocketAddr::from(([203, 0, 113, 10], 41000)),
            },
            SelectedPath::Direct {
                remote_address: SocketAddr::from(([198, 51, 100, 20], 32000)),
            },
        ),
    };
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::PathReady {
            session_id,
            route_mode,
            path: client_path,
        },
    )
    .await;
    let target_connection_id = runtime.target_connection_id;
    control::handle_agent_message(
        state,
        target_id,
        target_connection_id,
        ControlMessage::PathReady {
            session_id,
            route_mode,
            path: target_path,
        },
    )
    .await;
    (client_offer, dial_offer, target_data_endpoint_id)
}

async fn send_agent_iroh_ready_for_session(
    state: &ServerState,
    target_id: Uuid,
    connection_id: Uuid,
    session_id: Uuid,
    client_endpoint_id: String,
    target_data_endpoint_id: String,
    route_mode: RouteMode,
) {
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::IrohReady {
            session_id,
            client_endpoint_id,
            target_data_endpoint_id,
            route_mode,
        },
    )
    .await;
}

fn test_qad_ready(
    local_socket: SocketAddrV4,
    observed_addrs: [SocketAddrV4; 2],
) -> DiscoveryResult {
    DiscoveryResult::Ready {
        local_socket,
        observations: [
            QadObservation {
                reflector: QadReflector {
                    addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478),
                    server_name: "private-reflector".to_owned(),
                },
                local_socket,
                observed_addr: observed_addrs[0],
                handshake_confirmed: true,
                udp_tx_datagrams: 5,
                udp_rx_datagrams: 5,
                udp_tx_bytes: 500,
                udp_rx_bytes: 500,
            },
            QadObservation {
                reflector: QadReflector {
                    addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 7842),
                    server_name: "official-reflector".to_owned(),
                },
                local_socket,
                observed_addr: observed_addrs[1],
                handshake_confirmed: true,
                udp_tx_datagrams: 5,
                udp_rx_datagrams: 5,
                udp_tx_bytes: 500,
                udp_rx_bytes: 500,
            },
        ]
        .into(),
    }
}

struct BirthdayPunchControl<'a> {
    target_id: Uuid,
    connection_id: Uuid,
    device_key: &'a SecretKey,
    target_receiver: &'a mut mpsc::Receiver<ControlMessage>,
    client_sender: &'a mpsc::Sender<ControlMessage>,
    client_receiver: &'a mut mpsc::Receiver<ControlMessage>,
    session_id: Uuid,
    client_key: &'a SecretKey,
}

struct BirthdayPunchCandidates {
    target_local: SocketAddrV4,
    target_observed: [SocketAddrV4; 2],
    client_local: SocketAddrV4,
    client_observed: [SocketAddrV4; 2],
}

async fn start_test_birthday_punch(
    state: &ServerState,
    user: super::auth::AuthenticatedUser,
    control: BirthdayPunchControl<'_>,
    candidates: BirthdayPunchCandidates,
) -> String {
    let BirthdayPunchControl {
        target_id,
        connection_id,
        device_key,
        target_receiver,
        client_sender,
        client_receiver,
        session_id,
        client_key,
    } = control;
    let BirthdayPunchCandidates {
        target_local,
        target_observed,
        client_local,
        client_observed,
    } = candidates;
    control::open_tunnel(
        state,
        user,
        client_sender,
        session_id,
        target_id,
        client_key.public().to_string(),
        RouteMode::PrivateDirect,
    )
    .await
    .expect("open test birthday punch session");
    let expires_at = match target_receiver.recv().await.expect("target Prepare") {
        ControlMessage::Prepare {
            session_id: received,
            expires_at,
            ..
        } if received == session_id => expires_at,
        other => panic!("unexpected target control message: {other:?}"),
    };
    let target_data_key = SecretKey::generate();
    let signature = device_key
        .sign(&identity::agent_session_identity_payload(
            session_id,
            target_id,
            RouteMode::PrivateDirect,
            &target_data_key.public(),
            expires_at,
        ))
        .to_bytes()
        .to_vec();
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::AgentIdentity {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            target_data_endpoint_id: target_data_key.public().to_string(),
            signature,
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("target identity acceptance"),
        ControlMessage::IdentityAccepted { session_id: received, .. }
            if received == session_id
    ));
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::CandidatesReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            discovery: test_qad_ready(target_local, target_observed),
        },
    )
    .await;
    control::handle_client_message(
        state,
        user,
        client_sender,
        ControlMessage::CandidatesReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            discovery: test_qad_ready(client_local, client_observed),
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("client offer"),
        ControlMessage::ClientOffer { session_id: received, .. }
            if received == session_id
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("target punch pair"),
        ControlMessage::PunchPair { session_id: received, .. }
            if received == session_id
    ));
    assert!(matches!(
        client_receiver.recv().await.expect("client punch pair"),
        ControlMessage::PunchPair { session_id: received, .. }
            if received == session_id
    ));
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::PunchReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            socket_count: 257,
        },
    )
    .await;
    control::handle_client_message(
        state,
        user,
        client_sender,
        ControlMessage::PunchReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            socket_count: 1,
        },
    )
    .await;
    assert!(matches!(
        timeout(Duration::from_secs(2), target_receiver.recv())
            .await
            .expect("target StartPunch timed out")
            .expect("target control channel closed"),
        ControlMessage::StartPunch { session_id: received, .. }
            if received == session_id
    ));
    assert!(matches!(
        timeout(Duration::from_secs(2), client_receiver.recv())
            .await
            .expect("client StartPunch timed out")
            .expect("client control channel closed"),
        ControlMessage::StartPunch { session_id: received, .. }
            if received == session_id
    ));
    target_data_key.public().to_string()
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
async fn relay_access_scopes_target_data_identity_to_its_live_session() {
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
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(target_secret.public()))
            .await,
        Access::Deny { .. }
    ));

    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate relay test user");
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, _client_receiver) = mpsc::channel(16);
    let client_key = SecretKey::generate();
    let session_id = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        session_id,
        target_id,
        client_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open pending relay test session");
    assert!(matches!(
        target_receiver.recv().await.expect("target prepare"),
        ControlMessage::Prepare { session_id: received, .. } if received == session_id
    ));
    let data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        session_id,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(data_key.public()))
            .await,
        Access::Allow
    );
    control::close_pending_client_tunnels(state, &client_sender).await;
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(data_key.public()))
            .await,
        Access::Deny { .. }
    ));
}

#[tokio::test]
async fn per_session_target_identity_requires_the_enrolled_device_signature() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate identity test user");
    let device_key = SecretKey::generate();
    let (target_id, _) =
        create_enrolled_target(state, "identity-signature-target", &device_key).await;
    grant_target(state, target_id).await;
    let (connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, mut client_receiver) = mpsc::channel(16);
    let client_key = SecretKey::generate();
    let session_id = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        session_id,
        target_id,
        client_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open identity-signature session");
    let expires_at = match target_receiver.recv().await.expect("target Prepare") {
        ControlMessage::Prepare {
            session_id: received,
            expires_at,
            ..
        } if received == session_id => expires_at,
        other => panic!("unexpected target control message: {other:?}"),
    };

    let untrusted_device_key = SecretKey::generate();
    let data_key = SecretKey::generate();
    let signature = untrusted_device_key
        .sign(&identity::agent_session_identity_payload(
            session_id,
            target_id,
            RouteMode::PrivateRelay,
            &data_key.public(),
            expires_at,
        ))
        .to_bytes()
        .to_vec();
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::AgentIdentity {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            target_data_endpoint_id: data_key.public().to_string(),
            signature,
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("reject untrusted identity"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "agent_identity_rejected"
    ));
    assert!(matches!(
        client_receiver.recv().await.expect("report target identity failure"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "agent_identity_rejected"
    ));
    let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(session_id.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read rejected identity session");
    assert_eq!(status, "closed");
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(data_key.public()))
            .await,
        Access::Deny { .. }
    ));
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(device_key.public()))
            .await,
        Access::Deny { .. }
    ));
}

#[tokio::test]
async fn target_data_endpoint_id_is_once_bound_across_live_sessions() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate duplicate endpoint test user");
    let device_key = SecretKey::generate();
    let (target_id, _) =
        create_enrolled_target(state, "duplicate-data-id-target", &device_key).await;
    grant_target(state, target_id).await;
    let (connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_a_sender, mut client_a_receiver) = mpsc::channel(16);
    let (client_b_sender, mut client_b_receiver) = mpsc::channel(16);
    let client_a_key = SecretKey::generate();
    let client_b_key = SecretKey::generate();
    let session_a = Uuid::new_v4();
    let session_b = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_a_sender,
        session_a,
        target_id,
        client_a_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open first duplicate endpoint session");
    let expiry_a = match target_receiver.recv().await.expect("first Prepare") {
        ControlMessage::Prepare {
            session_id,
            expires_at,
            ..
        } if session_id == session_a => expires_at,
        other => panic!("unexpected target control message: {other:?}"),
    };
    let data_key = SecretKey::generate();
    let signature_a = device_key
        .sign(&identity::agent_session_identity_payload(
            session_a,
            target_id,
            RouteMode::PrivateRelay,
            &data_key.public(),
            expiry_a,
        ))
        .to_bytes()
        .to_vec();
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::AgentIdentity {
            session_id: session_a,
            route_mode: RouteMode::PrivateRelay,
            target_data_endpoint_id: data_key.public().to_string(),
            signature: signature_a,
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("accept first identity"),
        ControlMessage::IdentityAccepted { session_id, .. } if session_id == session_a
    ));
    assert!(matches!(
        client_a_receiver.recv().await.expect("first ClientOffer"),
        ControlMessage::ClientOffer { session_id, .. } if session_id == session_a
    ));
    assert!(matches!(
        client_a_receiver.recv().await.expect("first private relay plan"),
        ControlMessage::ContinueNative {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            plan: NativePlan::Standard,
        } if session_id == session_a
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("first target private relay plan"),
        ControlMessage::ContinueNative {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            plan: NativePlan::Standard,
        } if session_id == session_a
    ));

    let colliding_client_session = Uuid::new_v4();
    assert!(
        control::open_tunnel(
            state,
            user,
            &client_b_sender,
            colliding_client_session,
            target_id,
            data_key.public().to_string(),
            RouteMode::PrivateRelay,
        )
        .await
        .is_err()
    );

    control::open_tunnel(
        state,
        user,
        &client_b_sender,
        session_b,
        target_id,
        client_b_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open second duplicate endpoint session");
    let expiry_b = match target_receiver.recv().await.expect("second Prepare") {
        ControlMessage::Prepare {
            session_id,
            expires_at,
            ..
        } if session_id == session_b => expires_at,
        other => panic!("unexpected target control message: {other:?}"),
    };
    let signature_b = device_key
        .sign(&identity::agent_session_identity_payload(
            session_b,
            target_id,
            RouteMode::PrivateRelay,
            &data_key.public(),
            expiry_b,
        ))
        .to_bytes()
        .to_vec();
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::AgentIdentity {
            session_id: session_b,
            route_mode: RouteMode::PrivateRelay,
            target_data_endpoint_id: data_key.public().to_string(),
            signature: signature_b,
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("reject duplicate identity"),
        ControlMessage::Error { session_id: Some(session_id), code, .. }
            if session_id == session_b && code == "agent_identity_rejected"
    ));
    assert!(matches!(
        client_b_receiver.recv().await.expect("report duplicate identity"),
        ControlMessage::Error { session_id: Some(session_id), code, .. }
            if session_id == session_b && code == "agent_identity_rejected"
    ));
    let session_a_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(session_a.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read first session status");
    let session_b_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(session_b.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read second session status");
    assert_eq!(session_a_status, "pending");
    assert_eq!(session_b_status, "closed");
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(data_key.public()))
            .await,
        Access::Allow
    );
}

#[tokio::test]
async fn measured_candidate_pair_and_matching_punch_selection_reach_native_handoff() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate punch test user");
    let device_key = SecretKey::generate();
    let (target_id, _) = create_enrolled_target(state, "punch-state-target", &device_key).await;
    grant_target(state, target_id).await;
    let (connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, mut client_receiver) = mpsc::channel(32);
    let client_key = SecretKey::generate();
    let session_id = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        session_id,
        target_id,
        client_key.public().to_string(),
        RouteMode::PrivateDirect,
    )
    .await
    .expect("open measured punch session");
    let expires_at = match target_receiver.recv().await.expect("target Prepare") {
        ControlMessage::Prepare {
            session_id: received,
            expires_at,
            ..
        } if received == session_id => expires_at,
        other => panic!("unexpected target control message: {other:?}"),
    };
    let data_key = SecretKey::generate();
    let signature = device_key
        .sign(&identity::agent_session_identity_payload(
            session_id,
            target_id,
            RouteMode::PrivateDirect,
            &data_key.public(),
            expires_at,
        ))
        .to_bytes()
        .to_vec();
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::AgentIdentity {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            target_data_endpoint_id: data_key.public().to_string(),
            signature,
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("target identity acceptance"),
        ControlMessage::IdentityAccepted { session_id: received, .. }
            if received == session_id
    ));

    let target_local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 41000);
    let target_ip = Ipv4Addr::new(203, 0, 113, 10);
    let target_discovery = DiscoveryResult::Ready {
        local_socket: target_local,
        observations: vec![
            QadObservation {
                reflector: QadReflector {
                    addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478),
                    server_name: "private-reflector".to_owned(),
                },
                local_socket: target_local,
                observed_addr: SocketAddrV4::new(target_ip, 2100),
                handshake_confirmed: true,
                udp_tx_datagrams: 5,
                udp_rx_datagrams: 5,
                udp_tx_bytes: 500,
                udp_rx_bytes: 500,
            },
            QadObservation {
                reflector: QadReflector {
                    addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 7842),
                    server_name: "official-reflector".to_owned(),
                },
                local_socket: target_local,
                observed_addr: SocketAddrV4::new(target_ip, 2110),
                handshake_confirmed: true,
                udp_tx_datagrams: 5,
                udp_rx_datagrams: 5,
                udp_tx_bytes: 500,
                udp_rx_bytes: 500,
            },
        ],
    };
    let client_local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 42000);
    let client_observed = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 32000);
    let client_discovery = DiscoveryResult::Ready {
        local_socket: client_local,
        observations: vec![
            QadObservation {
                reflector: QadReflector {
                    addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478),
                    server_name: "private-reflector".to_owned(),
                },
                local_socket: client_local,
                observed_addr: client_observed,
                handshake_confirmed: true,
                udp_tx_datagrams: 5,
                udp_rx_datagrams: 5,
                udp_tx_bytes: 500,
                udp_rx_bytes: 500,
            },
            QadObservation {
                reflector: QadReflector {
                    addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 7842),
                    server_name: "official-reflector".to_owned(),
                },
                local_socket: client_local,
                observed_addr: client_observed,
                handshake_confirmed: true,
                udp_tx_datagrams: 5,
                udp_rx_datagrams: 5,
                udp_tx_bytes: 500,
                udp_rx_bytes: 500,
            },
        ],
    };
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::CandidatesReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            discovery: target_discovery,
        },
    )
    .await;
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::CandidatesReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            discovery: client_discovery,
        },
    )
    .await;
    let ControlMessage::ClientOffer { .. } = client_receiver.recv().await.expect("ClientOffer")
    else {
        panic!("client did not receive ClientOffer");
    };
    assert!(matches!(
        target_receiver.recv().await.expect("target receives peer candidates"),
        ControlMessage::PunchPair {
            session_id: received,
            target_endpoint_id,
            client_endpoint_id,
            peer_discovery: ReadyDiscovery { local_socket, .. },
            ..
        } if received == session_id
            && target_endpoint_id == data_key.public().to_string()
            && client_endpoint_id == client_key.public().to_string()
            && local_socket == client_local
    ));
    assert!(matches!(
        client_receiver.recv().await.expect("client receives peer candidates"),
        ControlMessage::PunchPair {
            session_id: received,
            peer_discovery: ReadyDiscovery { local_socket, observations, .. },
            ..
        } if received == session_id
            && local_socket == target_local
            && observations[0].observed_addr.port() == 2100
            && observations[1].observed_addr.port() == 2110
    ));

    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::PunchReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            socket_count: 257,
        },
    )
    .await;
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::PunchReady {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            socket_count: 1,
        },
    )
    .await;
    assert!(matches!(
        timeout(Duration::from_secs(2), target_receiver.recv())
            .await
            .expect("target StartPunch timed out")
            .expect("target control channel closed"),
        ControlMessage::StartPunch { session_id: received, .. } if received == session_id
    ));
    assert!(matches!(
        timeout(Duration::from_secs(2), client_receiver.recv())
            .await
            .expect("client StartPunch timed out")
            .expect("client control channel closed"),
        ControlMessage::StartPunch { session_id: received, .. } if received == session_id
    ));

    let target_peer_observed = client_observed;
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::PunchSelected {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            index: 7,
            local_socket: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 41001),
            peer_observed_addr: target_peer_observed,
        },
    )
    .await;
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::PunchSelected {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            index: 7,
            local_socket: client_local,
            peer_observed_addr: SocketAddrV4::new(target_ip, 2110),
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("target native handoff"),
        ControlMessage::ContinueNative {
            session_id: received,
            plan: NativePlan::Handoff { self_observed_addr, peer_observed_addr },
            ..
        } if received == session_id
            && self_observed_addr == SocketAddrV4::new(target_ip, 2110)
            && peer_observed_addr == target_peer_observed
    ));
    assert!(matches!(
        client_receiver.recv().await.expect("client native handoff"),
        ControlMessage::ContinueNative {
            session_id: received,
            plan: NativePlan::Handoff { self_observed_addr, peer_observed_addr },
            ..
        } if received == session_id
            && self_observed_addr == target_peer_observed
            && peer_observed_addr == SocketAddrV4::new(target_ip, 2110)
    ));
    control::close_pending_client_tunnels(state, &client_sender).await;
}

#[tokio::test]
async fn punch_selection_rejects_changed_client_tuple_out_of_range_and_mismatched_index() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate punch selection test user");
    let device_key = SecretKey::generate();
    let (target_id, _) = create_enrolled_target(state, "punch-selection-target", &device_key).await;
    grant_target(state, target_id).await;
    let (connection_id, mut target_receiver) = online_target(state, target_id).await;
    let target_local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 41000);
    let target_ip = Ipv4Addr::new(203, 0, 113, 10);
    let target_mappings = [
        SocketAddrV4::new(target_ip, 2100),
        SocketAddrV4::new(target_ip, 2110),
    ];
    let client_local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 42000);
    let client_mapping = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 32000);
    let client_mappings = [client_mapping, client_mapping];

    let (client_sender, mut client_receiver) = mpsc::channel(16);
    let client_key = SecretKey::generate();
    let session_id = Uuid::new_v4();
    start_test_birthday_punch(
        state,
        user,
        BirthdayPunchControl {
            target_id,
            connection_id,
            device_key: &device_key,
            target_receiver: &mut target_receiver,
            client_sender: &client_sender,
            client_receiver: &mut client_receiver,
            session_id,
            client_key: &client_key,
        },
        BirthdayPunchCandidates {
            target_local,
            target_observed: target_mappings,
            client_local,
            client_observed: client_mappings,
        },
    )
    .await;
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::PunchSelected {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            index: 0,
            local_socket: target_local,
            peer_observed_addr: client_mapping,
        },
    )
    .await;
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::PunchSelected {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            index: 0,
            local_socket: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, client_local.port() + 1),
            peer_observed_addr: SocketAddrV4::new(target_ip, 2110),
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("reject changed client tuple"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "client_punch_rejected"
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("notify target of bad client tuple"),
        ControlMessage::Error { session_id: Some(id), .. } if id == session_id
    ));

    let (client_sender, mut client_receiver) = mpsc::channel(16);
    let client_key = SecretKey::generate();
    let session_id = Uuid::new_v4();
    start_test_birthday_punch(
        state,
        user,
        BirthdayPunchControl {
            target_id,
            connection_id,
            device_key: &device_key,
            target_receiver: &mut target_receiver,
            client_sender: &client_sender,
            client_receiver: &mut client_receiver,
            session_id,
            client_key: &client_key,
        },
        BirthdayPunchCandidates {
            target_local,
            target_observed: target_mappings,
            client_local,
            client_observed: client_mappings,
        },
    )
    .await;
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::PunchSelected {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            index: 257,
            local_socket: target_local,
            peer_observed_addr: client_mapping,
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("reject out-of-range target index"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "agent_punch_rejected"
    ));
    assert!(matches!(
        client_receiver.recv().await.expect("notify client of bad target index"),
        ControlMessage::Error { session_id: Some(id), .. } if id == session_id
    ));

    let (client_sender, mut client_receiver) = mpsc::channel(16);
    let client_key = SecretKey::generate();
    let session_id = Uuid::new_v4();
    start_test_birthday_punch(
        state,
        user,
        BirthdayPunchControl {
            target_id,
            connection_id,
            device_key: &device_key,
            target_receiver: &mut target_receiver,
            client_sender: &client_sender,
            client_receiver: &mut client_receiver,
            session_id,
            client_key: &client_key,
        },
        BirthdayPunchCandidates {
            target_local,
            target_observed: target_mappings,
            client_local,
            client_observed: client_mappings,
        },
    )
    .await;
    control::handle_agent_message(
        state,
        target_id,
        connection_id,
        ControlMessage::PunchSelected {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            index: 7,
            local_socket: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, target_local.port() + 1),
            peer_observed_addr: client_mapping,
        },
    )
    .await;
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::PunchSelected {
            session_id,
            route_mode: RouteMode::PrivateDirect,
            index: 8,
            local_socket: client_local,
            peer_observed_addr: SocketAddrV4::new(target_ip, 2110),
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("reject mismatched punch index"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "client_punch_rejected"
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("notify target of mismatched index"),
        ControlMessage::Error { session_id: Some(id), .. } if id == session_id
    ));
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
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
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
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open pending SSH session");
    assert!(matches!(
        target_receiver.recv().await.expect("target preparation"),
        ControlMessage::Prepare { session_id: id, route_mode: RouteMode::PrivateRelay, .. } if id == denied_session_id
    ));
    let _denied_data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        denied_session_id,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    let relay_url: RelayUrl = reqwest::Url::parse(&state.inner.issuer)
        .expect("parse private relay URL")
        .into();
    let (client_offer, _dial_offer, denied_target_data_endpoint_id) =
        exchange_test_client_candidates(
            state,
            &mut client_receiver,
            &mut target_receiver,
            denied_session_id,
            &denied_client_key,
            RouteMode::PrivateRelay,
            relay_url.clone(),
        )
        .await;
    let ControlMessage::ClientOffer { ticket, .. } = client_offer else {
        unreachable!();
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
    assert_eq!(claims.target_endpoint_id, denied_target_data_endpoint_id);
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(denied_client_key.public()))
            .await,
        Access::Allow
    );
    revoke_target(state, target_id).await;
    send_agent_iroh_ready_for_session(
        state,
        target_id,
        target_connection_id,
        denied_session_id,
        denied_client_key.public().to_string(),
        denied_target_data_endpoint_id,
        RouteMode::PrivateRelay,
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
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open second pending SSH session");
    assert!(matches!(
        target_receiver.recv().await.expect("second target preparation"),
        ControlMessage::Prepare { session_id: id, route_mode: RouteMode::PrivateRelay, .. } if id == active_session_id
    ));
    let _active_data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        active_session_id,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    let (_, _, active_target_data_endpoint_id) = exchange_test_client_candidates(
        state,
        &mut client_receiver,
        &mut target_receiver,
        active_session_id,
        &active_client_key,
        RouteMode::PrivateRelay,
        relay_url,
    )
    .await;
    send_agent_iroh_ready_for_session(
        state,
        target_id,
        target_connection_id,
        active_session_id,
        active_client_key.public().to_string(),
        active_target_data_endpoint_id.clone(),
        RouteMode::PrivateRelay,
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
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(
                active_target_data_endpoint_id
                    .parse()
                    .expect("parse active target data EndpointId"),
            ))
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
async fn closing_client_control_only_closes_its_pending_tunnels() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let target_secret = SecretKey::generate();
    let (target_id, _) =
        create_enrolled_target(state, "control-owner-target", &target_secret).await;
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
    let private_relay_url: RelayUrl = reqwest::Url::parse(&state.inner.issuer)
        .expect("parse private relay URL")
        .into();
    let (sender_a, mut receiver_a) = mpsc::channel(32);
    let (sender_b, mut receiver_b) = mpsc::channel(32);

    let pending_a = Uuid::new_v4();
    let pending_a_key = SecretKey::generate();
    control::open_tunnel(
        state,
        user,
        &sender_a,
        pending_a,
        target_id,
        pending_a_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open sender A pending tunnel");
    assert!(matches!(
        target_receiver.recv().await.expect("sender A preparation"),
        ControlMessage::Prepare { session_id, .. } if session_id == pending_a
    ));

    let active_a = Uuid::new_v4();
    let active_a_key = SecretKey::generate();
    control::open_tunnel(
        state,
        user,
        &sender_a,
        active_a,
        target_id,
        active_a_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open sender A active tunnel");
    assert!(matches!(
        target_receiver.recv().await.expect("sender A active preparation"),
        ControlMessage::Prepare { session_id, .. } if session_id == active_a
    ));
    let _active_target_data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        active_a,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    let (_, _, active_target_data_endpoint_id) = exchange_test_client_candidates(
        state,
        &mut receiver_a,
        &mut target_receiver,
        active_a,
        &active_a_key,
        RouteMode::PrivateRelay,
        private_relay_url.clone(),
    )
    .await;
    let iroh_ready = ControlMessage::IrohReady {
        session_id: active_a,
        client_endpoint_id: active_a_key.public().to_string(),
        target_data_endpoint_id: active_target_data_endpoint_id.clone(),
        route_mode: RouteMode::PrivateRelay,
    };
    control::handle_client_message(state, user, &sender_a, iroh_ready.clone()).await;
    assert!(matches!(
        receiver_a.recv().await.expect("client cannot assert device readiness"),
        ControlMessage::Error { session_id: None, code, .. } if code == "invalid_direction"
    ));
    control::handle_agent_message(state, target_id, Uuid::new_v4(), iroh_ready.clone()).await;
    let pending_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(active_a.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read session after stale agent control");
    assert_eq!(pending_status, "pending");
    assert!(receiver_a.try_recv().is_err());
    assert!(target_receiver.try_recv().is_err());
    control::handle_agent_message(state, target_id, target_connection_id, iroh_ready).await;
    assert!(matches!(
        receiver_a.recv().await.expect("sender A activation"),
        ControlMessage::Activated { session_id } if session_id == active_a
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("target activation"),
        ControlMessage::Activated { session_id } if session_id == active_a
    ));

    let pending_b_one = Uuid::new_v4();
    let pending_b_one_key = SecretKey::generate();
    control::open_tunnel(
        state,
        user,
        &sender_b,
        pending_b_one,
        target_id,
        pending_b_one_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open sender B first pending tunnel");
    assert!(matches!(
        target_receiver.recv().await.expect("sender B first preparation"),
        ControlMessage::Prepare { session_id, .. } if session_id == pending_b_one
    ));
    let _pending_b_one_data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        pending_b_one,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    let (_, _, pending_b_one_target_data_endpoint_id) = exchange_test_client_candidates(
        state,
        &mut receiver_b,
        &mut target_receiver,
        pending_b_one,
        &pending_b_one_key,
        RouteMode::PrivateRelay,
        private_relay_url.clone(),
    )
    .await;

    let pending_b_two = Uuid::new_v4();
    let pending_b_two_key = SecretKey::generate();
    control::open_tunnel(
        state,
        user,
        &sender_b,
        pending_b_two,
        target_id,
        pending_b_two_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open sender B second pending tunnel");
    assert!(matches!(
        target_receiver.recv().await.expect("sender B second preparation"),
        ControlMessage::Prepare { session_id, .. } if session_id == pending_b_two
    ));
    let _pending_b_two_data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        pending_b_two,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    let (_, _, pending_b_two_target_data_endpoint_id) = exchange_test_client_candidates(
        state,
        &mut receiver_b,
        &mut target_receiver,
        pending_b_two,
        &pending_b_two_key,
        RouteMode::PrivateRelay,
        private_relay_url.clone(),
    )
    .await;

    control::close_pending_client_tunnels(state, &sender_a).await;
    assert!(matches!(
        receiver_a.recv().await.expect("sender A pending close"),
        ControlMessage::Close { session_id, .. } if session_id == pending_a
    ));
    assert!(
        receiver_a.try_recv().is_err(),
        "sender A active tunnel receives no close"
    );
    assert!(matches!(
        target_receiver.recv().await.expect("target pending close"),
        ControlMessage::Close { session_id, .. } if session_id == pending_a
    ));
    assert!(
        receiver_b.try_recv().is_err(),
        "sender B receives no close from sender A"
    );
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(active_a_key.public()))
            .await,
        Access::Allow
    );
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(
                active_target_data_endpoint_id
                    .parse()
                    .expect("parse active target data EndpointId"),
            ))
            .await,
        Access::Allow
    );

    let pending_a_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(pending_a.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read sender A pending status");
    let active_a_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(active_a.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read sender A active status");
    let pending_b_one_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(pending_b_one.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read sender B first pending status");
    let pending_b_two_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(pending_b_two.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read sender B second pending status");
    assert_eq!(pending_a_status, "closed");
    assert_eq!(active_a_status, "active");
    assert_eq!(pending_b_one_status, "pending");
    assert_eq!(pending_b_two_status, "pending");

    send_agent_iroh_ready_for_session(
        state,
        target_id,
        target_connection_id,
        pending_b_one,
        pending_b_one_key.public().to_string(),
        pending_b_one_target_data_endpoint_id,
        RouteMode::PrivateRelay,
    )
    .await;
    send_agent_iroh_ready_for_session(
        state,
        target_id,
        target_connection_id,
        pending_b_two,
        pending_b_two_key.public().to_string(),
        pending_b_two_target_data_endpoint_id,
        RouteMode::PrivateRelay,
    )
    .await;
    assert!(matches!(
        receiver_b.recv().await.expect("sender B first activation"),
        ControlMessage::Activated { session_id } if session_id == pending_b_one
    ));
    assert!(matches!(
        receiver_b.recv().await.expect("sender B second activation"),
        ControlMessage::Activated { session_id } if session_id == pending_b_two
    ));
    let pending_b_one_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(pending_b_one.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read activated sender B first status");
    let pending_b_two_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(pending_b_two.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read activated sender B second status");
    assert_eq!(pending_b_one_status, "active");
    assert_eq!(pending_b_two_status, "active");
}

#[tokio::test]
async fn target_control_disconnect_only_closes_its_pending_sessions() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate target disconnect test user");
    let device_key = SecretKey::generate();
    let (target_id, _) = create_enrolled_target(state, "target-control-owner", &device_key).await;
    grant_target(state, target_id).await;
    let (connection_id, mut target_receiver) = online_target(state, target_id).await;
    let relay_url: RelayUrl = reqwest::Url::parse(&state.inner.issuer)
        .expect("parse private relay URL")
        .into();

    let (pending_sender, mut pending_receiver) = mpsc::channel(32);
    let pending_client_key = SecretKey::generate();
    let pending_session = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &pending_sender,
        pending_session,
        target_id,
        pending_client_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open pending session");
    assert!(matches!(
        target_receiver.recv().await.expect("pending Prepare"),
        ControlMessage::Prepare { session_id, .. } if session_id == pending_session
    ));

    let (active_sender, mut active_receiver) = mpsc::channel(32);
    let active_client_key = SecretKey::generate();
    let active_session = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &active_sender,
        active_session,
        target_id,
        active_client_key.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open active session");
    assert!(matches!(
        target_receiver.recv().await.expect("active Prepare"),
        ControlMessage::Prepare { session_id, .. } if session_id == active_session
    ));
    let _active_data_key = send_agent_ready_for_session(
        state,
        target_id,
        connection_id,
        active_session,
        RouteMode::PrivateRelay,
        &device_key,
        &mut target_receiver,
    )
    .await;
    let (_, _, active_target_data_endpoint_id) = exchange_test_client_candidates(
        state,
        &mut active_receiver,
        &mut target_receiver,
        active_session,
        &active_client_key,
        RouteMode::PrivateRelay,
        relay_url,
    )
    .await;
    send_agent_iroh_ready_for_session(
        state,
        target_id,
        connection_id,
        active_session,
        active_client_key.public().to_string(),
        active_target_data_endpoint_id.clone(),
        RouteMode::PrivateRelay,
    )
    .await;
    assert!(matches!(
        active_receiver.recv().await.expect("active client activation"),
        ControlMessage::Activated { session_id } if session_id == active_session
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("active target activation"),
        ControlMessage::Activated { session_id } if session_id == active_session
    ));

    control::unregister_agent(state, target_id, connection_id).await;
    assert!(matches!(
        pending_receiver.recv().await.expect("pending client close"),
        ControlMessage::Close { session_id, .. } if session_id == pending_session
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("pending target close"),
        ControlMessage::Close { session_id, .. } if session_id == pending_session
    ));
    assert!(active_receiver.try_recv().is_err());

    let pending_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(pending_session.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read pending session status");
    let active_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(active_session.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read active session status");
    assert_eq!(pending_status, "closed");
    assert_eq!(active_status, "active");
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(active_client_key.public()))
            .await,
        Access::Allow
    );
    assert_eq!(
        state
            .on_connect(&endpoint_connect_request(
                active_target_data_endpoint_id
                    .parse()
                    .expect("parse active target data EndpointId"),
            ))
            .await,
        Access::Allow
    );
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(pending_client_key.public()))
            .await,
        Access::Deny { .. }
    ));
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(device_key.public()))
            .await,
        Access::Deny { .. }
    ));
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

    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
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
            RouteMode::PrivateRelay,
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
        RouteMode::PublicDirect,
    )
    .await
    .expect("public mode remains available without a private relay");
    assert!(matches!(
        target_receiver.recv().await.expect("target preparation"),
        ControlMessage::Prepare { session_id: received, route_mode: RouteMode::PublicDirect, .. }
            if received == session_id
    ));
    let data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        session_id,
        RouteMode::PublicDirect,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    let ControlMessage::ClientOffer {
        ticket,
        target_endpoint_id,
        route_mode: RouteMode::PublicDirect,
        ..
    } = client_receiver.recv().await.expect("client offer")
    else {
        panic!("client received another control message");
    };
    assert_eq!(target_endpoint_id, data_key.public().to_string());
    let claims: TunnelTicketClaims = identity::decode_tunnel_ticket(
        &ticket,
        &state.inner.keys.tunnel_ticket.public_key_pem,
        &state.inner.issuer,
    )
    .expect("decode public-mode ticket");
    assert_eq!(claims.route_mode, RouteMode::PublicDirect);
    assert_eq!(claims.target_endpoint_id, data_key.public().to_string());
    assert!(matches!(
        client_receiver.recv().await.expect("public native transport plan"),
        ControlMessage::ContinueNative {
            session_id: id,
            route_mode: RouteMode::PublicDirect,
            plan: NativePlan::Standard,
        } if id == session_id
    ));
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::ClientReady {
            session_id,
            route_mode: RouteMode::PublicDirect,
            client_endpoint_addr: EndpointAddr::new(client_secret.public())
                .with_ip_addr(SocketAddr::from(([198, 51, 100, 20], 32000))),
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("target dial offer"),
        ControlMessage::DialOffer { session_id: received, route_mode: RouteMode::PublicDirect, .. }
            if received == session_id
    ));
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::PathReady {
            session_id,
            route_mode: RouteMode::PublicDirect,
            path: SelectedPath::Direct {
                remote_address: SocketAddr::from(([203, 0, 113, 10], 41000)),
            },
        },
    )
    .await;
    send_agent_iroh_ready_for_session(
        state,
        target_id,
        target_connection_id,
        session_id,
        client_secret.public().to_string(),
        data_key.public().to_string(),
        RouteMode::PublicDirect,
    )
    .await;
    let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(session_id.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read route-gated public session status");
    assert_eq!(status, "pending");
    control::handle_agent_message(
        state,
        target_id,
        target_connection_id,
        ControlMessage::PathReady {
            session_id,
            route_mode: RouteMode::PublicDirect,
            path: SelectedPath::Direct {
                remote_address: SocketAddr::from(([198, 51, 100, 20], 32000)),
            },
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("public direct activation"),
        ControlMessage::Activated { session_id: received } if received == session_id
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("target public direct activation"),
        ControlMessage::Activated { session_id: received } if received == session_id
    ));
}

#[tokio::test]
async fn public_direct_attempt_rejects_a_relay_data_path() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate public direct test user");
    let device_key = SecretKey::generate();
    let (target_id, _) = create_enrolled_target(state, "public-direct-target", &device_key).await;
    grant_target(state, target_id).await;
    let (connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, mut client_receiver) = mpsc::channel(16);
    let client_key = SecretKey::generate();
    let session_id = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        session_id,
        target_id,
        client_key.public().to_string(),
        RouteMode::PublicDirect,
    )
    .await
    .expect("open public direct attempt");
    assert!(matches!(
        target_receiver.recv().await.expect("target preparation"),
        ControlMessage::Prepare { session_id: received, .. } if received == session_id
    ));
    let target_data_key = send_agent_ready_for_session(
        state,
        target_id,
        connection_id,
        session_id,
        RouteMode::PublicDirect,
        &device_key,
        &mut target_receiver,
    )
    .await;
    let ControlMessage::ClientOffer {
        session_id: offered,
        ..
    } = client_receiver.recv().await.expect("client offer")
    else {
        panic!("client received another message instead of ClientOffer");
    };
    assert_eq!(offered, session_id);
    assert!(matches!(
        client_receiver.recv().await.expect("public direct plan"),
        ControlMessage::ContinueNative {
            session_id: planned,
            route_mode: RouteMode::PublicDirect,
            plan: NativePlan::Standard,
        } if planned == session_id
    ));
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::ClientReady {
            session_id,
            route_mode: RouteMode::PublicDirect,
            client_endpoint_addr: EndpointAddr::new(client_key.public())
                .with_ip_addr(SocketAddr::from(([198, 51, 100, 20], 32000))),
        },
    )
    .await;
    assert!(matches!(
        target_receiver.recv().await.expect("target dial offer"),
        ControlMessage::DialOffer { session_id: offered, .. } if offered == session_id
    ));
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::PathReady {
            session_id,
            route_mode: RouteMode::PublicDirect,
            path: SelectedPath::PrivateRelay {
                url: "https://kmesh.test/".to_owned(),
            },
        },
    )
    .await;
    let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(session_id.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read rejected public relay session");
    assert_eq!(status, "closed");
    assert!(matches!(
        client_receiver.recv().await.expect("client path rejection"),
        ControlMessage::Error { session_id: Some(received), code, .. }
            if received == session_id && code == "client_path_rejected"
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("target path rejection"),
        ControlMessage::Error { session_id: Some(received), code, .. }
            if received == session_id && code == "client_path_rejected"
    ));
    assert!(matches!(
        state
            .on_connect(&endpoint_connect_request(target_data_key.public()))
            .await,
        Access::Deny { .. }
    ));
}

#[tokio::test]
async fn client_ready_is_bound_to_its_open_control_and_endpoint_identity() {
    let fixture = fixture("https://kmesh.test").await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let target_secret = SecretKey::generate();
    let (target_id, _) = create_enrolled_target(state, "client-ready-target", &target_secret).await;
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, mut client_receiver) = mpsc::channel(32);
    let (other_sender, mut other_receiver) = mpsc::channel(32);
    let client_secret = SecretKey::generate();
    let session_id = Uuid::new_v4();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        session_id,
        target_id,
        client_secret.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open SSH session for ClientReady ownership test");
    assert!(matches!(
        target_receiver.recv().await.expect("target preparation"),
        ControlMessage::Prepare { session_id: received, .. } if received == session_id
    ));
    let _data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        session_id,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    let client_offer = client_receiver
        .recv()
        .await
        .expect("client receives endpoint offer");
    assert!(
        matches!(client_offer, ControlMessage::ClientOffer { session_id: id, .. } if id == session_id)
    );
    assert!(matches!(
        client_receiver.recv().await.expect("client native plan"),
        ControlMessage::ContinueNative {
            session_id: id,
            route_mode: RouteMode::PrivateRelay,
            plan: NativePlan::Standard,
        } if id == session_id
    ));

    let private_relay: RelayUrl = reqwest::Url::parse(&state.inner.issuer)
        .expect("parse private relay URL")
        .into();
    let candidate = EndpointAddr::new(client_secret.public()).with_relay_url(private_relay.clone());
    control::handle_client_message(
        state,
        user,
        &other_sender,
        ControlMessage::ClientReady {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            client_endpoint_addr: candidate.clone(),
        },
    )
    .await;
    assert!(matches!(
        other_receiver.recv().await.expect("reject another control connection"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "client_ready_denied"
    ));
    let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(session_id.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read pending session status");
    assert_eq!(
        status, "pending",
        "another control socket cannot cancel this session"
    );
    assert!(target_receiver.try_recv().is_err());

    let wrong_endpoint = SecretKey::generate();
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::ClientReady {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            client_endpoint_addr: EndpointAddr::new(wrong_endpoint.public())
                .with_relay_url(private_relay),
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("reject mismatched client EndpointId"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "client_ready_denied"
    ));
    assert!(matches!(
        target_receiver.recv().await.expect("notify agent about rejected endpoint"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == session_id && code == "client_ready_denied"
    ));
    let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(session_id.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read rejected session status");
    assert_eq!(status, "closed");

    let mode_session = Uuid::new_v4();
    let mode_client_secret = SecretKey::generate();
    control::open_tunnel(
        state,
        user,
        &client_sender,
        mode_session,
        target_id,
        mode_client_secret.public().to_string(),
        RouteMode::PrivateRelay,
    )
    .await
    .expect("open SSH session for relay-mode rejection test");
    assert!(matches!(
        target_receiver.recv().await.expect("target preparation"),
        ControlMessage::Prepare { session_id: received, .. } if received == mode_session
    ));
    let mode_data_key = send_agent_ready_for_session(
        state,
        target_id,
        target_connection_id,
        mode_session,
        RouteMode::PrivateRelay,
        &target_secret,
        &mut target_receiver,
    )
    .await;
    client_receiver
        .recv()
        .await
        .expect("client receives endpoint offer");
    assert!(matches!(
        client_receiver.recv().await.expect("client native plan"),
        ControlMessage::ContinueNative {
            session_id: id,
            route_mode: RouteMode::PrivateRelay,
            plan: NativePlan::Standard,
        } if id == mode_session
    ));
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::IrohReady {
            session_id: mode_session,
            client_endpoint_id: mode_client_secret.public().to_string(),
            target_data_endpoint_id: mode_data_key.public().to_string(),
            route_mode: RouteMode::PrivateRelay,
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("reject client-originated device proof"),
        ControlMessage::Error { session_id: None, code, .. } if code == "invalid_direction"
    ));
    control::handle_client_message(
        state,
        user,
        &client_sender,
        ControlMessage::ClientReady {
            session_id: mode_session,
            route_mode: RouteMode::PublicDirect,
            client_endpoint_addr: EndpointAddr::new(mode_client_secret.public())
                .with_relay_url(reqwest::Url::parse(&state.inner.issuer).unwrap().into()),
        },
    )
    .await;
    assert!(matches!(
        client_receiver.recv().await.expect("reject mismatched relay mode"),
        ControlMessage::Error { session_id: Some(id), code, .. }
            if id == mode_session && code == "client_ready_denied"
    ));
    let status: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(mode_session.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read mode-rejected session status");
    assert_eq!(status, "closed");
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
async fn self_hosted_https_private_relay_and_activated_ssh_stream_work_together() {
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
        quic_port: relay_server.qad_addr().port(),
    };
    let endpoint_options = IrohEndpointOptions {
        relay_choice: relay_choice.clone(),
        tls: tls.clone(),
        handoff: None,
    };
    let mut agent_control = connect_control_ws(&issuer, "agent/control", &agent_token, &tls).await;

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
            route_mode: RouteMode::PrivateRelay,
        },
    )
    .await;
    let ControlMessage::Prepare {
        session_id: prepared_session_id,
        client_endpoint_id: prepared_client_endpoint_id,
        expires_at,
        route_mode: RouteMode::PrivateRelay,
    } = timeout(Duration::from_secs(10), receive_control(&mut agent_control))
        .await
        .expect("timed out waiting for target prepare")
    else {
        panic!("target received a non-prepare message");
    };
    assert_eq!(prepared_session_id, session_id);
    assert_eq!(
        prepared_client_endpoint_id,
        client_secret.public().to_string()
    );
    let target_data_secret = SecretKey::generate();
    let target_data_endpoint_id = target_data_secret.public().to_string();
    let identity_signature = target_secret
        .sign(&identity::agent_session_identity_payload(
            session_id,
            target_id,
            RouteMode::PrivateRelay,
            &target_data_secret.public(),
            expires_at,
        ))
        .to_bytes()
        .to_vec();
    send_control(
        &mut agent_control,
        &ControlMessage::AgentIdentity {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            target_data_endpoint_id: target_data_endpoint_id.clone(),
            signature: identity_signature,
        },
    )
    .await;
    assert!(matches!(
        timeout(Duration::from_secs(10), receive_control(&mut agent_control))
            .await
            .expect("target identity acceptance timed out"),
        ControlMessage::IdentityAccepted { session_id: received, route_mode: RouteMode::PrivateRelay }
            if received == session_id
    ));
    assert!(
        control::allow_agent_data_endpoint(state, &target_data_endpoint_id)
            .await
            .expect("check pending target data relay access"),
        "signed target data identity should be authorized for this pending session"
    );
    let ControlMessage::ClientOffer {
        session_id: client_offer_id,
        target_id: offered_target_id,
        ticket,
        client_endpoint_id,
        target_endpoint_id,
        ticket_public_key_pem,
        route_mode: RouteMode::PrivateRelay,
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
    assert_eq!(offered_target_id, target_id);
    assert_eq!(target_endpoint_id, target_data_endpoint_id);
    let claims: TunnelTicketClaims =
        identity::decode_tunnel_ticket(&ticket, &ticket_public_key_pem, &issuer)
            .expect("verify server ticket");
    assert_eq!(claims.client_endpoint_id, client_endpoint_id);
    assert_eq!(claims.target_endpoint_id, target_data_endpoint_id);

    for control in [&mut agent_control, &mut client_control] {
        assert!(matches!(
            timeout(Duration::from_secs(10), receive_control(control))
                .await
                .expect("native transport plan timed out"),
            ControlMessage::ContinueNative {
                session_id: received,
                route_mode: RouteMode::PrivateRelay,
                plan: NativePlan::Standard,
            } if received == session_id
        ));
    }

    let target_endpoint = create_endpoint(target_data_secret, false, endpoint_options.clone())
        .await
        .expect("create per-session target Iroh endpoint");
    timeout(Duration::from_secs(15), target_endpoint.online())
        .await
        .expect("target did not connect to the private relay");
    assert_eq!(target_endpoint.id().to_string(), target_data_endpoint_id);
    send_control(
        &mut agent_control,
        &ControlMessage::AgentReady {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            endpoint_addr: EndpointAddr::new(target_endpoint.id())
                .with_relay_url(relay_url.clone()),
        },
    )
    .await;

    let client_endpoint = create_endpoint(client_secret, true, endpoint_options)
        .await
        .expect("create SSH client Iroh endpoint");
    timeout(Duration::from_secs(15), client_endpoint.online())
        .await
        .expect("client did not connect to the private relay");
    let client_endpoint_addr =
        EndpointAddr::new(client_endpoint.id()).with_relay_url(relay_url.clone());
    let client_accept = {
        let endpoint = client_endpoint.clone();
        tokio::spawn(async move { accept_peer(&endpoint).await })
    };
    send_control(
        &mut client_control,
        &ControlMessage::ClientReady {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            client_endpoint_addr: client_endpoint_addr.clone(),
        },
    )
    .await;
    let ControlMessage::DialOffer {
        session_id: dial_session_id,
        target_id: dial_target_id,
        ticket: dial_ticket,
        client_endpoint_id: dial_client_endpoint_id,
        client_endpoint_addr: dial_client_endpoint_addr,
        ticket_public_key_pem: dial_ticket_public_key,
        route_mode: RouteMode::PrivateRelay,
    } = timeout(Duration::from_secs(10), receive_control(&mut agent_control))
        .await
        .expect("timed out waiting for target dial offer")
    else {
        panic!("target received a non-dial-offer control message");
    };
    assert_eq!(dial_session_id, session_id);
    assert_eq!(dial_target_id, target_id);
    assert_eq!(dial_ticket, ticket);
    assert_eq!(dial_client_endpoint_id, client_endpoint_id);
    assert_eq!(dial_client_endpoint_addr, client_endpoint_addr);
    assert_eq!(dial_ticket_public_key, ticket_public_key_pem);
    let claims: TunnelTicketClaims =
        identity::decode_tunnel_ticket(&dial_ticket, &dial_ticket_public_key, &issuer)
            .expect("verify target dial ticket");
    assert_eq!(claims.target_endpoint_id, target_endpoint.id().to_string());

    let connection = timeout(
        Duration::from_secs(15),
        connect_peer(&target_endpoint, dial_client_endpoint_addr, &relay_choice),
    )
    .await
    .expect("Iroh peer connection timed out")
    .expect("target connects through the self-hosted relay");
    let selected_target_path = timeout(
        Duration::from_secs(10),
        wait_for_selected_path(
            &connection,
            RouteMode::PrivateRelay,
            tokio::time::Instant::now() + Duration::from_secs(10),
        ),
    )
    .await
    .expect("target did not select the configured private relay")
    .expect("read target selected path");
    send_control(
        &mut agent_control,
        &ControlMessage::PathReady {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            path: selected_target_path,
        },
    )
    .await;
    let mut target_stream = IrohByteStream::open_bi(connection)
        .await
        .expect("target opens SSH stream");
    target_stream
        .write_u32(ticket.len() as u32)
        .await
        .expect("write target ticket frame length");
    target_stream
        .write_all(ticket.as_bytes())
        .await
        .expect("write target signed ticket");

    let accepted = timeout(Duration::from_secs(15), client_accept)
        .await
        .expect("client did not accept target endpoint")
        .expect("target accept task panicked")
        .expect("accept Iroh peer");
    let selected_client_path = timeout(
        Duration::from_secs(10),
        wait_for_selected_path(
            &accepted,
            RouteMode::PrivateRelay,
            tokio::time::Instant::now() + Duration::from_secs(10),
        ),
    )
    .await
    .expect("client did not select the configured private relay")
    .expect("read client selected path");
    send_control(
        &mut client_control,
        &ControlMessage::PathReady {
            session_id,
            route_mode: RouteMode::PrivateRelay,
            path: selected_client_path,
        },
    )
    .await;
    assert_eq!(
        accepted.remote_id().to_string(),
        target_endpoint.id().to_string()
    );
    let mut client_stream = IrohByteStream::accept_bi(accepted)
        .await
        .expect("client accepts SSH stream");
    let received_ticket_size = client_stream
        .read_u32()
        .await
        .expect("read client ticket length") as usize;
    let mut received_ticket = vec![0; received_ticket_size];
    client_stream
        .read_exact(&mut received_ticket)
        .await
        .expect("read client ticket");
    assert_eq!(received_ticket, ticket.as_bytes());
    assert_eq!(
        client_stream.connection().remote_id().to_string(),
        target_endpoint.id().to_string()
    );
    send_control(
        &mut agent_control,
        &ControlMessage::IrohReady {
            session_id,
            client_endpoint_id,
            target_data_endpoint_id,
            route_mode: RouteMode::PrivateRelay,
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
