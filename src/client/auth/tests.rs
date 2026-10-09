use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde::{Serialize, de::DeserializeOwned};
use ssh_key::{PublicKey, SshSig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::{
    client::{
        ClientContext,
        api::Api,
        profile::{ProfileStore, SavedSession},
    },
    config::{AuthConfig, AuthMethod, Config},
    protocol::{LoginTokens, PublicKeyChallenge, PublicKeyChallengeRequest, PublicKeyLoginRequest},
};

use super::*;

const REFRESH_CHILD_ENV: &str = "KMESH_TEST_REFRESH_CHILD";
const TOKEN_CHILD_ENV: &str = "KMESH_TEST_TOKEN_CHILD";
const SSH_AGENT_CHILD_PUBLIC_KEY_ENV: &str = "KMESH_TEST_SSH_AGENT_PUBLIC_KEY";
const SSH_AGENT_CHILD_INPUT_ENV: &str = "KMESH_TEST_SSH_AGENT_INPUT";
const SSH_AGENT_CHILD_OUTPUT_ENV: &str = "KMESH_TEST_SSH_AGENT_OUTPUT";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("kmesh-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create client auth test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn server_address_and_port(origin: &str) -> (String, u16) {
    let origin = reqwest::Url::parse(origin).expect("valid test server origin");
    (
        origin
            .host_str()
            .expect("test server hostname")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        origin.port_or_known_default().expect("test server port"),
    )
}

async fn auth_context(config: Config) -> ClientContext {
    let api = Api::new(&config).await.expect("build test API client");
    let profiles = ProfileStore::new(
        &config.data_dir,
        &config.server_origin().expect("test server origin"),
        &config.profile,
    );
    ClientContext {
        config,
        api,
        profiles,
    }
}

fn generate_ssh_key(directory: &Path, name: &str) -> PathBuf {
    let private_key = directory.join(name);
    let output = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private_key)
        .output()
        .expect("run ssh-keygen for client test key");
    assert!(output.status.success(), "ssh-keygen generated a test key");
    private_key
}

fn test_tls_acceptor() -> TlsAcceptor {
    TlsAcceptor::from(
        crate::transport::tls::server_config().expect("build production mTLS server config"),
    )
}

async fn read_http_request(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .expect("read HTTP header");
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(request.len() < 16 * 1024, "HTTP headers are bounded");
    }
    let content_length = String::from_utf8_lossy(&request)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content length"))
        })
        .unwrap_or(0);
    let mut body = vec![0; content_length];
    stream.read_exact(&mut body).await.expect("read HTTP body");
    request.extend_from_slice(&body);
    request
}

fn request_json<T: DeserializeOwned>(request: &[u8]) -> T {
    let body_offset = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP request headers end")
        + 4;
    serde_json::from_slice(&request[body_offset..]).expect("decode HTTP request body")
}

async fn respond_json(stream: &mut (impl AsyncWrite + Unpin), value: &impl Serialize) {
    let body = serde_json::to_vec(value).expect("encode HTTP response");
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write HTTP response headers");
    stream
        .write_all(&body)
        .await
        .expect("write HTTP response body");
    stream.shutdown().await.expect("close HTTP response");
}

async fn one_public_key_authentication(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    expected_public_key: String,
    tokens: LoginTokens,
) {
    let (socket, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("challenge request arrives")
        .expect("accept challenge request");
    let mut stream = timeout(Duration::from_secs(5), acceptor.accept(socket))
        .await
        .expect("challenge HTTPS handshake completes")
        .expect("accept challenge HTTPS");
    let request = timeout(Duration::from_secs(5), read_http_request(&mut stream))
        .await
        .expect("challenge request completes");
    let request_text = String::from_utf8_lossy(&request);
    assert!(request_text.starts_with("POST /v1/auth/challenge "));
    let challenge_request: PublicKeyChallengeRequest = request_json(&request);
    assert_eq!(challenge_request.username, "alice");
    assert_eq!(challenge_request.public_key, expected_public_key);

    let challenge_bytes = b"server challenge payload";
    let challenge_id = Uuid::new_v4();
    respond_json(
        &mut stream,
        &PublicKeyChallenge {
            challenge_id,
            challenge: URL_SAFE_NO_PAD.encode(challenge_bytes),
            expires_at: unix_now().expect("current time") + 60,
        },
    )
    .await;

    let (socket, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("signature request arrives")
        .expect("accept signature request");
    let mut stream = timeout(Duration::from_secs(5), acceptor.accept(socket))
        .await
        .expect("signature HTTPS handshake completes")
        .expect("accept signature HTTPS");
    let request = timeout(Duration::from_secs(5), read_http_request(&mut stream))
        .await
        .expect("signature request completes");
    let request_text = String::from_utf8_lossy(&request);
    assert!(request_text.starts_with("POST /v1/auth/public-key "));
    let login_request: PublicKeyLoginRequest = request_json(&request);
    assert_eq!(login_request.username, "alice");
    assert_eq!(login_request.challenge_id, challenge_id);
    let signature = SshSig::from_pem(login_request.signature.as_bytes())
        .expect("parse SSHSIG challenge signature");
    PublicKey::from_openssh(&expected_public_key)
        .expect("parse SSH public key")
        .verify("kmesh-login", challenge_bytes, &signature)
        .expect("verify configured SSH key signed the challenge");
    respond_json(&mut stream, &tokens).await;
}

async fn one_refresh_request(
    listener_and_acceptor: (TcpListener, TlsAcceptor),
    expected_refresh_token: &'static str,
    reply: Option<LoginTokens>,
    delay: Duration,
    request_count: Arc<AtomicUsize>,
    request_seen: Option<oneshot::Sender<()>>,
    release_reply: Option<oneshot::Receiver<()>>,
) {
    let (listener, acceptor) = listener_and_acceptor;
    let (socket, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("refresh request arrives")
        .expect("accept refresh request");
    let mut stream = timeout(Duration::from_secs(5), acceptor.accept(socket))
        .await
        .expect("HTTPS handshake completes")
        .expect("accept HTTPS refresh");
    let request = timeout(Duration::from_secs(5), read_http_request(&mut stream))
        .await
        .expect("refresh HTTP request completes");
    assert_eq!(
        request_json::<crate::protocol::RefreshRequest>(&request).refresh_token,
        expected_refresh_token
    );
    request_count.fetch_add(1, Ordering::SeqCst);
    if let Some(request_seen) = request_seen {
        let _ = request_seen.send(());
    }
    if let Some(release_reply) = release_reply {
        timeout(Duration::from_secs(5), release_reply)
            .await
            .expect("test releases the refresh response")
            .expect("refresh response release signal");
    } else {
        sleep(delay).await;
    }
    if let Some(reply) = reply {
        respond_json(&mut stream, &reply).await;
    }
}

#[tokio::test]
async fn token_environment_overrides_config_and_token_is_returned_directly() {
    let executable = std::env::current_exe().expect("resolve auth test executable");
    for (mode, environment_token) in [
        ("config", None),
        ("environment", Some("environment-token")),
        ("empty", Some("")),
    ] {
        let mut command = Command::new(&executable);
        command
            .args([
                "--exact",
                "client::auth::tests::token_environment_child",
                "--nocapture",
            ])
            .env(TOKEN_CHILD_ENV, mode);
        if let Some(token) = environment_token {
            command.env("KMESH_TOKEN", token);
        } else {
            command.env_remove("KMESH_TOKEN");
        }
        let output = command.output().expect("run isolated token test process");
        assert!(
            output.status.success(),
            "isolated token process succeeds: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn token_environment_child() {
    let Ok(mode) = std::env::var(TOKEN_CHILD_ENV) else {
        return;
    };
    let directory = TestDirectory::new("token-source-test");
    let context = auth_context(Config {
        data_dir: directory.0.clone(),
        auth: AuthConfig {
            method: Some(AuthMethod::Token),
            token: Some("config-token".to_owned()),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    match mode.as_str() {
        "config" => assert_eq!(
            super::valid_access_token(&context).await.unwrap(),
            "config-token"
        ),
        "environment" => assert_eq!(
            super::valid_access_token(&context).await.unwrap(),
            "environment-token"
        ),
        "empty" => assert_eq!(
            super::valid_access_token(&context)
                .await
                .unwrap_err()
                .to_string(),
            "API token is empty"
        ),
        mode => panic!("unexpected token test mode {mode}"),
    }
    assert!(!context.profiles.session_path("alice").exists());
}

#[tokio::test]
async fn missing_auth_method_reports_the_required_config_setting() {
    let context = auth_context(Config::default()).await;
    let error = super::valid_access_token(&context)
        .await
        .expect_err("authentication requires a configured method");
    assert_eq!(
        error.to_string(),
        "Set [auth].method to token or public-key in the configuration."
    );
}

#[tokio::test]
async fn configured_ssh_key_authenticates_on_demand_and_session_matches_key_identity() {
    let directory = TestDirectory::new("on-demand-public-key-test");
    let old_key_path = generate_ssh_key(&directory.0, "old_id_ed25519");
    let key_path = generate_ssh_key(&directory.0, "id_ed25519");
    let expected_public_key = public_key(&key_path).expect("extract configured public key");
    let expected_fingerprint = public_key_fingerprint(&expected_public_key).unwrap();
    let old_fingerprint = public_key_fingerprint(&public_key(&old_key_path).unwrap()).unwrap();
    let acceptor = test_tls_acceptor();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind local public-key auth server");
    let server_port = listener.local_addr().unwrap().port();
    let now = unix_now().unwrap();
    let tokens = LoginTokens {
        access_token: "fresh-access-token".to_owned(),
        refresh_token: "fresh-refresh-token".to_owned(),
        access_expires_at: now + 900,
        refresh_expires_at: now + 30 * 24 * 60 * 60,
    };
    let server = tokio::spawn(one_public_key_authentication(
        listener,
        acceptor,
        expected_public_key.clone(),
        tokens.clone(),
    ));
    let context = auth_context(Config {
        server_addr: "127.0.0.1".to_owned(),
        server_port,
        data_dir: directory.0.clone(),
        auth: AuthConfig {
            method: Some(AuthMethod::PublicKey),
            username: Some("Alice".to_owned()),
            key: Some(key_path),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    context
        .profiles
        .save(
            "alice",
            &SavedSession {
                public_key_fingerprint: old_fingerprint,
                tokens: LoginTokens {
                    access_token: "wrong-key-access-token".to_owned(),
                    refresh_token: "wrong-key-refresh-token".to_owned(),
                    access_expires_at: now + 900,
                    refresh_expires_at: now + 30 * 24 * 60 * 60,
                },
            },
        )
        .expect("save session for a different SSH key");

    let access_token = super::valid_access_token(&context)
        .await
        .expect("authenticate with the configured SSH key");
    server.await.expect("public-key auth server completes");
    assert_eq!(access_token, "fresh-access-token");
    let saved = context.profiles.load("alice").unwrap().unwrap();
    assert_eq!(saved.public_key_fingerprint, expected_fingerprint);
    assert_eq!(saved.tokens.refresh_token, "fresh-refresh-token");
    assert_eq!(
        super::valid_access_token(&context).await.unwrap(),
        "fresh-access-token"
    );
}

struct SshAgent {
    socket: String,
    pid: String,
}

impl Drop for SshAgent {
    fn drop(&mut self) {
        let _ = Command::new("ssh-agent")
            .arg("-k")
            .env("SSH_AUTH_SOCK", &self.socket)
            .env("SSH_AGENT_PID", &self.pid)
            .output();
    }
}

#[tokio::test]
async fn ssh_agent_signing_child() {
    let (Some(public_key), Some(input_path), Some(output_path)) = (
        std::env::var_os(SSH_AGENT_CHILD_PUBLIC_KEY_ENV),
        std::env::var_os(SSH_AGENT_CHILD_INPUT_ENV),
        std::env::var_os(SSH_AGENT_CHILD_OUTPUT_ENV),
    ) else {
        return;
    };
    let payload = fs::read(input_path).expect("read SSHSIG agent payload");
    let signature = sign_sshsig(Path::new(&public_key), &payload).expect("sign with SSH agent");
    fs::write(output_path, signature).expect("write SSHSIG agent result");
}

#[tokio::test]
async fn sshsig_signing_uses_loaded_agent_key_from_public_key_path() {
    let directory = TestDirectory::new("ssh-agent-test");
    let private_key = generate_ssh_key(&directory.0, "id_ed25519");
    let public_key_path = private_key.with_extension("pub");
    let socket = format!("/tmp/kmesh-agent-{}.sock", Uuid::new_v4());
    let agent_output = Command::new("ssh-agent")
        .args(["-a", &socket, "-s"])
        .output()
        .expect("start local OpenSSH agent");
    assert!(agent_output.status.success(), "ssh-agent started");
    let agent_output = String::from_utf8(agent_output.stdout).expect("decode ssh-agent output");
    let assignment = |name: &str| {
        agent_output
            .lines()
            .find_map(|line| {
                line.strip_prefix(&format!("{name}="))
                    .map(|value| value.split(';').next().unwrap().to_owned())
            })
            .expect("ssh-agent reported shell variable")
    };
    let agent = SshAgent {
        socket: assignment("SSH_AUTH_SOCK"),
        pid: assignment("SSH_AGENT_PID"),
    };
    let added = Command::new("ssh-add")
        .arg(&private_key)
        .env("SSH_AUTH_SOCK", &agent.socket)
        .output()
        .expect("load test key into ssh-agent");
    assert!(added.status.success(), "ssh-add loaded the key");

    let input_path = directory.0.join("challenge.bin");
    let output_path = directory.0.join("challenge.sig");
    let payload = b"kmesh ssh-agent SSHSIG acceptance payload";
    fs::write(&input_path, payload).expect("write SSHSIG payload");
    let child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "client::auth::tests::ssh_agent_signing_child",
            "--nocapture",
        ])
        .env("SSH_AUTH_SOCK", &agent.socket)
        .env("SSH_AGENT_PID", &agent.pid)
        .env(SSH_AGENT_CHILD_PUBLIC_KEY_ENV, &public_key_path)
        .env(SSH_AGENT_CHILD_INPUT_ENV, &input_path)
        .env(SSH_AGENT_CHILD_OUTPUT_ENV, &output_path)
        .output()
        .await
        .expect("run isolated SSH agent signer");
    assert!(child.status.success(), "isolated SSH agent signer passed");
    let public_key = PublicKey::from_openssh(
        &fs::read_to_string(&public_key_path).expect("read SSH agent public key"),
    )
    .expect("parse SSH agent public key");
    let signature = SshSig::from_pem(
        fs::read_to_string(&output_path)
            .expect("read SSH agent signature")
            .as_bytes(),
    )
    .expect("parse SSH agent signature");
    public_key
        .verify("kmesh-login", payload, &signature)
        .expect("verify SSH agent signature");
    drop(agent);
}

#[tokio::test]
async fn refresh_process_child() {
    if std::env::var_os(REFRESH_CHILD_ENV).is_none() {
        return;
    }
    let server_url = std::env::var("KMESH_TEST_REFRESH_SERVER").expect("refresh test server URL");
    let data_dir = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_DATA").expect("data dir"));
    let key_path = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_KEY").expect("key path"));
    let output = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_OUTPUT").expect("output file"));
    let ready = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_READY").expect("ready file"));
    let go = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_GO").expect("start gate"));
    let (server_addr, server_port) = server_address_and_port(&server_url);
    let config = Config {
        server_addr,
        server_port,
        data_dir: data_dir.clone(),
        profile: "shared-profile".to_owned(),
        auth: AuthConfig {
            method: Some(AuthMethod::PublicKey),
            username: Some("alice".to_owned()),
            key: Some(key_path),
            ..AuthConfig::default()
        },
        ..Config::default()
    };
    let api = Api::new(&config).await.expect("build API client");
    let profiles = ProfileStore::new(
        &config.data_dir,
        &config.server_origin().expect("test server origin"),
        &config.profile,
    );
    let context = ClientContext {
        config,
        api,
        profiles,
    };
    fs::write(ready, b"ready").expect("signal refresh process ready");
    timeout(Duration::from_secs(5), async {
        while !go.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("parent releases refresh processes");
    let token = super::valid_access_token(&context)
        .await
        .expect("obtain concurrently refreshed access token");
    fs::write(output, token).expect("write child refresh result");
}

#[tokio::test]
async fn concurrent_process_refreshes_rotate_once_and_share_saved_session() {
    let directory = TestDirectory::new("refresh-process-test");
    let key_path = generate_ssh_key(&directory.0, "id_ed25519");
    let fingerprint = public_key_fingerprint(&public_key(&key_path).unwrap()).unwrap();
    let acceptor = test_tls_acceptor();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind local refresh server");
    let server_url = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let now = unix_now().unwrap();
    let profiles = ProfileStore::new(&directory.0, &server_url, "shared-profile");
    profiles
        .save(
            "alice",
            &SavedSession {
                public_key_fingerprint: fingerprint,
                tokens: LoginTokens {
                    access_token: "expired-access-token".to_owned(),
                    refresh_token: "old-refresh-token".to_owned(),
                    access_expires_at: now - 1,
                    refresh_expires_at: now + 3600,
                },
            },
        )
        .expect("save expired test session");

    let new_tokens = LoginTokens {
        access_token: "rotated-access-token".to_owned(),
        refresh_token: "rotated-refresh-token".to_owned(),
        access_expires_at: now + 900,
        refresh_expires_at: now + 30 * 24 * 60 * 60,
    };
    let request_count = Arc::new(AtomicUsize::new(0));
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let (release_reply_tx, release_reply_rx) = oneshot::channel();
    let server = tokio::spawn(one_refresh_request(
        (listener, acceptor),
        "old-refresh-token",
        Some(new_tokens),
        Duration::ZERO,
        request_count.clone(),
        Some(request_seen_tx),
        Some(release_reply_rx),
    ));

    let executable = std::env::current_exe().expect("resolve unit test executable");
    let first_output = directory.0.join("child-one.token");
    let second_output = directory.0.join("child-two.token");
    let first_ready = directory.0.join("child-one.ready");
    let second_ready = directory.0.join("child-two.ready");
    let go = directory.0.join("children.go");
    let child_args = [
        "--exact",
        "client::auth::tests::refresh_process_child",
        "--nocapture",
    ];
    let mut first = tokio::process::Command::new(&executable);
    first
        .args(child_args)
        .env(REFRESH_CHILD_ENV, "1")
        .env("KMESH_TEST_REFRESH_SERVER", &server_url)
        .env("KMESH_TEST_REFRESH_DATA", &directory.0)
        .env("KMESH_TEST_REFRESH_KEY", &key_path)
        .env("KMESH_TEST_REFRESH_OUTPUT", &first_output)
        .env("KMESH_TEST_REFRESH_READY", &first_ready)
        .env("KMESH_TEST_REFRESH_GO", &go)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut second = tokio::process::Command::new(&executable);
    second
        .args(child_args)
        .env(REFRESH_CHILD_ENV, "1")
        .env("KMESH_TEST_REFRESH_SERVER", &server_url)
        .env("KMESH_TEST_REFRESH_DATA", &directory.0)
        .env("KMESH_TEST_REFRESH_KEY", &key_path)
        .env("KMESH_TEST_REFRESH_OUTPUT", &second_output)
        .env("KMESH_TEST_REFRESH_READY", &second_ready)
        .env("KMESH_TEST_REFRESH_GO", &go)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let first = first.spawn().expect("start first refresh process");
    let second = second.spawn().expect("start second refresh process");
    timeout(Duration::from_secs(5), async {
        while !first_ready.exists() || !second_ready.exists() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("both refresh processes reach the refresh gate");
    fs::write(&go, b"go").expect("release both refresh processes");
    timeout(Duration::from_secs(5), request_seen_rx)
        .await
        .expect("first refresh request reaches mock server")
        .expect("refresh request notification");
    sleep(Duration::from_millis(100)).await;
    release_reply_tx
        .send(())
        .expect("release the rotated token response");
    let (first, second) = tokio::join!(first.wait_with_output(), second.wait_with_output());
    let first = first.expect("wait for first refresh process");
    let second = second.expect("wait for second refresh process");
    server.await.expect("refresh server task completes");
    assert!(first.status.success(), "first refresh process succeeds");
    assert!(
        second.status.success(),
        "second refresh process reuses rotation"
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read_to_string(first_output).unwrap(),
        "rotated-access-token"
    );
    assert_eq!(
        fs::read_to_string(second_output).unwrap(),
        "rotated-access-token"
    );
    let saved = profiles.load("alice").unwrap().unwrap();
    assert_eq!(saved.tokens.refresh_token, "rotated-refresh-token");
}

#[tokio::test]
async fn uncertain_refresh_clears_cached_session() {
    let directory = TestDirectory::new("uncertain-refresh-test");
    let key_path = generate_ssh_key(&directory.0, "id_ed25519");
    let fingerprint = public_key_fingerprint(&public_key(&key_path).unwrap()).unwrap();
    let acceptor = test_tls_acceptor();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind local refresh server");
    let server_url = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let now = unix_now().unwrap();
    let profiles = ProfileStore::new(&directory.0, &server_url, "uncertain-profile");
    profiles
        .save(
            "alice",
            &SavedSession {
                public_key_fingerprint: fingerprint,
                tokens: LoginTokens {
                    access_token: "expired-access-token".to_owned(),
                    refresh_token: "unknown-result-refresh-token".to_owned(),
                    access_expires_at: now - 1,
                    refresh_expires_at: now + 3600,
                },
            },
        )
        .expect("save session before uncertain refresh");
    let request_count = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(one_refresh_request(
        (listener, acceptor),
        "unknown-result-refresh-token",
        None,
        Duration::ZERO,
        request_count.clone(),
        None,
        None,
    ));

    let (server_addr, server_port) = server_address_and_port(&server_url);
    let context = auth_context(Config {
        server_addr,
        server_port,
        data_dir: directory.0.clone(),
        profile: "uncertain-profile".to_owned(),
        auth: AuthConfig {
            method: Some(AuthMethod::PublicKey),
            username: Some("alice".to_owned()),
            key: Some(key_path),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    let error = super::valid_access_token(&context)
        .await
        .expect_err("an uncertain refresh fails clearly");
    assert!(format!("{error:#}").contains("authenticate with the configured SSH key"));
    server
        .await
        .expect("uncertain refresh server task completes");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    assert!(context.profiles.load("alice").unwrap().is_none());
}
