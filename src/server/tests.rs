use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

use crate::identity;
use crate::protocol::{
    AdminOperation, AdminResponse, AgentEnrollmentRequest, ControlMessage, LocalCandidate,
    LoginTokens, NatObservation, PasswordLoginRequest, PublicKeyChallengeRequest,
    PublicKeyLoginRequest, RefreshRequest, SelectedPath, StunMapping, TargetPermission,
};

use super::control::{self, OnlineAgent, TunnelPhase};
use super::{PersistedKeys, ServerInner, ServerState, auth, db::Database};

struct Fixture {
    state: ServerState,
    data_dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

async fn fixture() -> Fixture {
    let data_dir = std::env::temp_dir().join(format!("kmesh-server-test-{}", Uuid::new_v4()));
    super::initialize(
        &data_dir,
        "Admin",
        "initial-admin-password",
        "https://kmesh.test",
    )
    .await
    .expect("initialize test server");
    let first_key_bytes =
        std::fs::read(data_dir.join("token-keys.json")).expect("read generated keys");
    super::initialize(&data_dir, "other", "ignored-password", "https://kmesh.test")
        .await
        .expect("repeat server initialization");
    let second_key_bytes =
        std::fs::read(data_dir.join("token-keys.json")).expect("read persistent keys");
    assert_eq!(first_key_bytes, second_key_bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data_dir.join("token-keys.json"))
            .expect("stat key file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    let db = Database::open(data_dir.join("server.sqlite3"))
        .await
        .expect("open test DB");
    db.apply_schema().await.expect("apply test schema");
    let keys = PersistedKeys::from_slice(&first_key_bytes)
        .expect("decode generated keys")
        .into_token_keys();
    Fixture {
        state: ServerState {
            inner: Arc::new(ServerInner {
                db,
                issuer: "https://kmesh.test".to_owned(),
                keys,
                auth_rate_limiter: auth::AuthRateLimiter::default(),
                online_agents: RwLock::new(std::collections::HashMap::new()),
                tunnels: RwLock::new(std::collections::HashMap::new()),
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

#[test]
fn nat_plan_samples_only_the_measured_stable_same_ip_interval() {
    let client = NatObservation {
        local_candidates: vec![LocalCandidate {
            address: "10.0.0.6:51304"
                .parse()
                .expect("client local address"),
            prefix_len: 24,
        }],
        stun_mappings: [
            ("192.0.2.11:3478", Some("192.0.2.12:11326")),
            ("192.0.2.13:3478", Some("192.0.2.12:11326")),
            ("192.0.2.11:3478", Some("192.0.2.12:11326")),
        ]
        .map(|(server, mapped)| StunMapping {
            server: server.parse().expect("STUN server address"),
            mapped: mapped.map(|address| address.parse().expect("mapped address")),
        })
        .into(),
    };
    let target = NatObservation {
        local_candidates: vec![LocalCandidate {
            address: "10.0.0.4:43709"
                .parse()
                .expect("target local address"),
            prefix_len: 23,
        }],
        stun_mappings: [
            ("192.0.2.11:3478", Some("192.0.2.19:4164")),
            ("192.0.2.13:3478", Some("192.0.2.19:4148")),
            ("192.0.2.11:3478", Some("192.0.2.19:4164")),
        ]
        .map(|(server, mapped)| StunMapping {
            server: server.parse().expect("STUN server address"),
            mapped: mapped.map(|address| address.parse().expect("mapped address")),
        })
        .into(),
    };

    let plan = control::build_nat_plan(&client, &target);
    assert_eq!(plan.client_remote_candidates.len(), 8);
    assert_eq!(
        &plan.client_remote_candidates[..2],
        &[
            "192.0.2.19:4164".parse().expect("A mapping"),
            "192.0.2.19:4148".parse().expect("B mapping"),
        ]
    );
    assert!(plan.client_remote_candidates.iter().all(|candidate| {
        candidate.ip() == "192.0.2.19".parse::<IpAddr>().expect("public IP")
            && (4148..=4164).contains(&candidate.port())
    }));
    assert_eq!(
        plan.target_remote_candidates,
        vec!["192.0.2.12:11326".parse().expect("client mapping")]
    );
    assert_eq!(
        plan.client_remote_candidates
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        plan.client_remote_candidates.len(),
        "candidate order is stable and entries are unique"
    );
}

#[test]
fn nat_plan_adds_lan_candidates_only_for_overlapping_prefixes() {
    let client = NatObservation {
        local_candidates: vec![LocalCandidate {
            address: "10.0.0.3:5000".parse().expect("client local address"),
            prefix_len: 24,
        }],
        stun_mappings: vec![],
    };
    let target = NatObservation {
        local_candidates: vec![LocalCandidate {
            address: "10.0.0.4:5001".parse().expect("target local address"),
            prefix_len: 23,
        }],
        stun_mappings: vec![],
    };
    let plan = control::build_nat_plan(&client, &target);
    assert_eq!(
        plan.client_remote_candidates,
        vec!["10.0.0.4:5001".parse().unwrap()]
    );
    assert_eq!(
        plan.target_remote_candidates,
        vec!["10.0.0.3:5000".parse().unwrap()]
    );

    let non_overlapping_client = NatObservation {
        local_candidates: vec![LocalCandidate {
            address: "10.0.0.6:5000".parse().expect("client local address"),
            prefix_len: 24,
        }],
        stun_mappings: vec![],
    };
    let plan = control::build_nat_plan(&non_overlapping_client, &target);
    assert!(plan.client_remote_candidates.is_empty());
    assert!(plan.target_remote_candidates.is_empty());
}

#[test]
fn nat_plan_does_not_interpolate_unstable_or_cross_ip_observations() {
    let client = NatObservation {
        local_candidates: vec![],
        stun_mappings: vec![],
    };
    let target = NatObservation {
        local_candidates: vec![],
        stun_mappings: [
            ("192.0.2.11:3478", Some("192.0.2.19:4164")),
            ("192.0.2.13:3478", Some("198.51.100.2:4148")),
            ("192.0.2.11:3478", Some("192.0.2.19:4163")),
        ]
        .map(|(server, mapped)| StunMapping {
            server: server.parse().expect("STUN server address"),
            mapped: mapped.map(|address| address.parse().expect("mapped address")),
        })
        .into(),
    };

    let plan = control::build_nat_plan(&client, &target);
    assert_eq!(
        plan.client_remote_candidates,
        vec![
            "192.0.2.19:4164".parse().unwrap(),
            "198.51.100.2:4148".parse().unwrap(),
            "192.0.2.19:4163".parse().unwrap(),
        ]
    );
}

#[test]
fn nat_observation_validation_bounds_network_input() {
    assert!(control::valid_nat_observation(&NatObservation {
        local_candidates: vec![LocalCandidate {
            address: "10.0.0.2:1234".parse().unwrap(),
            prefix_len: 24,
        }],
        stun_mappings: vec![],
    }));
    assert!(!control::valid_nat_observation(&NatObservation {
        local_candidates: vec![LocalCandidate {
            address: "10.0.0.2:1234".parse().unwrap(),
            prefix_len: 33,
        }],
        stun_mappings: vec![],
    }));
    assert!(!control::valid_nat_observation(&NatObservation {
        local_candidates: vec![],
        stun_mappings: vec![],
    }));
}

#[tokio::test]
async fn control_sends_nat_plan_only_after_both_endpoints_report() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let (target_id, _) = create_enrolled_target(state, "nat-plan-target").await;
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, mut client_receiver) = mpsc::channel(16);
    let session_id = Uuid::new_v4();
    open_test_tunnel(
        state,
        user,
        session_id,
        target_id,
        target_connection_id,
        client_sender.clone(),
    )
    .await;
    let _ = target_receiver.recv().await.expect("target offer");
    let _ = client_receiver.recv().await.expect("client offer");

    let client_observation = NatObservation {
        local_candidates: vec![],
        stun_mappings: vec![StunMapping {
            server: "192.0.2.11:3478".parse().expect("STUN server address"),
            mapped: Some("198.51.100.10:5000".parse().expect("client mapped address")),
        }],
    };
    let target_observation = NatObservation {
        local_candidates: vec![],
        stun_mappings: vec![StunMapping {
            server: "192.0.2.11:3478".parse().expect("STUN server address"),
            mapped: Some("203.0.113.20:6000".parse().expect("target mapped address")),
        }],
    };
    control::submit_nat_observation(
        state,
        session_id,
        control::Endpoint::Client(user),
        Some(&client_sender),
        client_observation,
    )
    .await
    .expect("accept client observation");
    assert!(client_receiver.try_recv().is_err());
    assert!(target_receiver.try_recv().is_err());

    control::submit_nat_observation(
        state,
        session_id,
        control::Endpoint::Target {
            target_id,
            connection_id: target_connection_id,
        },
        None,
        target_observation,
    )
    .await
    .expect("accept target observation");

    let ControlMessage::NatPlan {
        session_id: client_session,
        plan: client_plan,
    } = client_receiver.recv().await.expect("client NAT plan")
    else {
        panic!("client receives NAT plan after both reports");
    };
    let ControlMessage::NatPlan {
        session_id: target_session,
        plan: target_plan,
    } = target_receiver.recv().await.expect("target NAT plan")
    else {
        panic!("target receives NAT plan after both reports");
    };
    assert_eq!(client_session, session_id);
    assert_eq!(target_session, session_id);
    assert_eq!(
        client_plan.client_remote_candidates,
        vec!["203.0.113.20:6000".parse().expect("target candidate")]
    );
    assert_eq!(
        client_plan.target_remote_candidates,
        vec!["198.51.100.10:5000".parse().expect("client candidate")]
    );
    assert_eq!(
        target_plan.client_remote_candidates,
        client_plan.client_remote_candidates
    );
    assert_eq!(
        target_plan.target_remote_candidates,
        client_plan.target_remote_candidates
    );
}

async fn admin_role_id(state: &ServerState) -> Uuid {
    sqlx::query_scalar::<_, String>("SELECT id FROM roles WHERE name = 'admin'")
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read admin role")
        .parse()
        .expect("parse admin role ID")
}

async fn create_enrolled_target(state: &ServerState, name: &str) -> (Uuid, String) {
    let created = super::admin::apply_operation(
        state,
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
    let target_certificate = identity::generate_target_certificate(target.target_id)
        .expect("generate test target certificate");
    let mut pem = Cursor::new(target_certificate.certificate_pem.as_bytes());
    let certificate_der = rustls_pemfile::certs(&mut pem)
        .next()
        .expect("target certificate exists")
        .expect("parse target certificate")
        .as_ref()
        .to_vec();
    let enrolled = control::enroll(
        State(state.clone()),
        Json(AgentEnrollmentRequest {
            target_id: target.target_id,
            enrollment_token: enrollment_token.clone(),
            certificate_der: certificate_der.clone(),
        }),
    )
    .await
    .expect("enroll target agent")
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
            certificate_der,
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
) -> (Uuid, mpsc::Receiver<crate::protocol::ControlMessage>) {
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

async fn open_test_tunnel(
    state: &ServerState,
    user: auth::AuthenticatedUser,
    session_id: Uuid,
    target_id: Uuid,
    target_connection_id: Uuid,
    client_sender: mpsc::Sender<crate::protocol::ControlMessage>,
) {
    control::open_tunnel(
        state,
        user,
        &client_sender,
        session_id,
        target_id,
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
    )
    .await
    .expect("open tunnel");
    assert_eq!(
        state
            .inner
            .tunnels
            .read()
            .await
            .get(&session_id)
            .expect("tunnel runtime inserted")
            .target_connection_id,
        target_connection_id
    );
}

#[tokio::test]
async fn sshsig_comment_canonicalization_and_challenge_replay() {
    let fixture = fixture().await;
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
    let admin_id = sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE username = 'admin'")
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read initial admin")
        .parse::<Uuid>()
        .expect("parse user id");
    super::admin::apply_operation(
        state,
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
    let fixture = fixture().await;
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
async fn enrollment_rbac_activation_and_quic_retention() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let (target_id, agent_token) = create_enrolled_target(state, "machine-a").await;
    let auth_headers = bearer(&agent_token);
    assert_eq!(
        control::authenticate_agent(state, &auth_headers)
            .await
            .expect("device token"),
        target_id
    );
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, mut client_receiver) = mpsc::channel(64);

    let denied_session = Uuid::new_v4();
    open_test_tunnel(
        state,
        user,
        denied_session,
        target_id,
        target_connection_id,
        client_sender.clone(),
    )
    .await;
    let _ = target_receiver.recv().await.expect("target offer");
    let _ = client_receiver.recv().await.expect("client offer");
    let pending_runtime = state
        .inner
        .tunnels
        .read()
        .await
        .get(&denied_session)
        .cloned()
        .expect("pending tunnel runtime");
    {
        let mut pending_state = pending_runtime.state.lock().await;
        pending_state.client_quic_ready = true;
        pending_state.target_quic_ready = true;
    }
    revoke_target(state, target_id).await;
    control::activate_path(
        state,
        target_id,
        target_connection_id,
        denied_session,
        SelectedPath::Quic,
    )
    .await;
    let denied_status =
        sqlx::query_scalar::<_, String>("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(denied_session.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read denied path status");
    assert_eq!(denied_status, "closed");
    assert!(
        !state
            .inner
            .tunnels
            .read()
            .await
            .contains_key(&denied_session)
    );

    grant_target(state, target_id).await;
    let active_session = Uuid::new_v4();
    open_test_tunnel(
        state,
        user,
        active_session,
        target_id,
        target_connection_id,
        client_sender.clone(),
    )
    .await;
    let _ = target_receiver.recv().await.expect("target offer");
    let _ = client_receiver.recv().await.expect("client offer");
    let runtime = state
        .inner
        .tunnels
        .read()
        .await
        .get(&active_session)
        .cloned()
        .expect("pending runtime");
    {
        let mut status = runtime.state.lock().await;
        status.client_quic_ready = true;
        status.target_quic_ready = true;
    }
    control::activate_path(
        state,
        target_id,
        target_connection_id,
        active_session,
        SelectedPath::Quic,
    )
    .await;
    assert!(
        !state
            .inner
            .tunnels
            .read()
            .await
            .contains_key(&active_session),
        "direct active state leaves coordination memory"
    );
    let (status, path): (String, Option<String>) =
        sqlx::query_as("SELECT status, selected_path FROM tunnel_sessions WHERE id = ?1")
            .bind(active_session.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read active direct audit record");
    assert_eq!(status, "active");
    assert_eq!(path.as_deref(), Some("quic"));

    revoke_target(state, target_id).await;
    auth::logout(State(state.clone()), bearer(&login.access_token))
        .await
        .expect("logout");
    let retained: String = sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
        .bind(active_session.to_string())
        .fetch_one(&state.inner.db.pool)
        .await
        .expect("read retained direct session");
    assert_eq!(
        retained, "active",
        "RBAC revoke and logout preserve activated SSH sessions"
    );
}

#[tokio::test]
async fn relay_selection_and_direct_activation_have_one_path_winner() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let (target_id, _) = create_enrolled_target(state, "machine-race").await;
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (client_sender, mut client_receiver) = mpsc::channel(64);
    let session_id = Uuid::new_v4();
    open_test_tunnel(
        state,
        user,
        session_id,
        target_id,
        target_connection_id,
        client_sender,
    )
    .await;
    let _ = target_receiver.recv().await.expect("target offer");
    let _ = client_receiver.recv().await.expect("client offer");
    if let Some(runtime) = state.inner.tunnels.read().await.get(&session_id).cloned() {
        let mut status = runtime.state.lock().await;
        status.client_quic_ready = true;
        status.target_quic_ready = true;
    }
    let (activate, relay) = tokio::join!(
        control::activate_path(
            state,
            target_id,
            target_connection_id,
            session_id,
            SelectedPath::Quic
        ),
        control::select_relay(state, session_id, control::Endpoint::Client(user)),
    );
    let _ = (activate, relay);
    if let Some(runtime) = state.inner.tunnels.read().await.get(&session_id).cloned()
        && runtime.state.lock().await.phase == TunnelPhase::RelaySelected
    {
        control::activate_path(
            state,
            target_id,
            target_connection_id,
            session_id,
            SelectedPath::Relay,
        )
        .await;
    }
    let (status, path): (String, Option<String>) =
        sqlx::query_as("SELECT status, selected_path FROM tunnel_sessions WHERE id = ?1")
            .bind(session_id.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read raced path record");
    assert_eq!(status, "active");
    assert!(matches!(path.as_deref(), Some("quic" | "relay")));
    if let Some(runtime) = state.inner.tunnels.read().await.get(&session_id).cloned() {
        assert_eq!(
            runtime.state.lock().await.phase,
            TunnelPhase::Active(SelectedPath::Relay)
        );
    } else {
        assert_eq!(path.as_deref(), Some("quic"));
    }
}

#[tokio::test]
async fn closing_one_control_socket_keeps_another_same_session_socket_alive() {
    let fixture = fixture().await;
    let state = &fixture.state;
    let login = login_password(state).await;
    let user = auth::authenticate(state, &bearer(&login.access_token))
        .await
        .expect("authenticate admin");
    let (target_id, _) = create_enrolled_target(state, "machine-control").await;
    grant_target(state, target_id).await;
    let (target_connection_id, mut target_receiver) = online_target(state, target_id).await;
    let (first_sender, mut first_receiver) = mpsc::channel(32);
    let (second_sender, mut second_receiver) = mpsc::channel(32);
    let first_session = Uuid::new_v4();
    let second_session = Uuid::new_v4();
    open_test_tunnel(
        state,
        user,
        first_session,
        target_id,
        target_connection_id,
        first_sender.clone(),
    )
    .await;
    open_test_tunnel(
        state,
        user,
        second_session,
        target_id,
        target_connection_id,
        second_sender.clone(),
    )
    .await;
    let _ = first_receiver.recv().await.expect("first offer");
    let _ = target_receiver.recv().await.expect("first target offer");
    let _ = second_receiver.recv().await.expect("second offer");
    let _ = target_receiver.recv().await.expect("second target offer");

    control::close_pending_user_tunnels(state, user.user_id, user.session_id, &first_sender).await;
    assert!(
        !state
            .inner
            .tunnels
            .read()
            .await
            .contains_key(&first_session)
    );
    let second_runtime = state
        .inner
        .tunnels
        .read()
        .await
        .get(&second_session)
        .cloned()
        .expect("second control connection session remains");
    {
        let mut status = second_runtime.state.lock().await;
        status.client_quic_ready = true;
        status.target_quic_ready = true;
    }
    control::activate_path(
        state,
        target_id,
        target_connection_id,
        second_session,
        SelectedPath::Quic,
    )
    .await;
    let second_status: String =
        sqlx::query_scalar("SELECT status FROM tunnel_sessions WHERE id = ?1")
            .bind(second_session.to_string())
            .fetch_one(&state.inner.db.pool)
            .await
            .expect("read second session state");
    assert_eq!(second_status, "active");
    assert!(
        !state
            .inner
            .tunnels
            .read()
            .await
            .contains_key(&second_session)
    );
}

const TEST_PRIVATE_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----"#;
