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

use clap::Parser;
use ssh_key::{PublicKey, SshSig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::{
    client::{
        Cli, ClientContext, Command as ClientCommand,
        api::Api,
        profile::{ProfileStore, SavedCredential, SavedLogin},
    },
    config::{AuthConfig, Config, LoginMethod},
    protocol::{LoginTokens, MeView, UserView},
};

use super::*;

const REFRESH_CHILD_ENV: &str = "KMESH_TEST_REFRESH_CHILD";
const SSH_AGENT_CHILD_PUBLIC_KEY_ENV: &str = "KMESH_TEST_SSH_AGENT_PUBLIC_KEY";
const SSH_AGENT_CHILD_INPUT_ENV: &str = "KMESH_TEST_SSH_AGENT_INPUT";
const SSH_AGENT_CHILD_OUTPUT_ENV: &str = "KMESH_TEST_SSH_AGENT_OUTPUT";
const TOKEN_ENV_CHILD: &str = "KMESH_TEST_TOKEN_ENV_CHILD";

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

#[tokio::test]
async fn login_reports_missing_method_token_username_and_key_before_network() {
    let context = auth_context(Config::default()).await;
    let error = super::login(&context, &LoginArgs::default())
        .await
        .expect_err("login requires an explicit method");
    assert!(format!("{error:#}").contains("Login method is required"));

    let context = auth_context(Config {
        auth: AuthConfig {
            method: Some(LoginMethod::Token),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    let error = super::login(&context, &LoginArgs::default())
        .await
        .expect_err("token login requires a token");
    assert!(format!("{error:#}").contains("API token is required"));

    let context = auth_context(Config {
        auth: AuthConfig {
            method: Some(LoginMethod::PublicKey),
            key: Some("/tmp/id_ed25519".into()),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    let error = super::login(&context, &LoginArgs::default())
        .await
        .expect_err("public-key login requires a username");
    assert!(format!("{error:#}").contains("--username or auth.username"));

    let context = auth_context(Config {
        auth: AuthConfig {
            method: Some(LoginMethod::PublicKey),
            username: Some("alice".to_owned()),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    let error = super::login(&context, &LoginArgs::default())
        .await
        .expect_err("public-key login requires a key");
    assert!(format!("{error:#}").contains("--key or auth.key"));
}

#[tokio::test]
async fn cli_public_key_settings_override_toml_and_expand_home_key_path() {
    let cli = Cli::try_parse_from([
        "kmesh",
        "login",
        "--method",
        "public-key",
        "--username",
        "cli-user",
        "--key",
        "~/kmesh-login-test-missing-key",
    ])
    .expect("parse public-key login overrides");
    let ClientCommand::Login(args) = cli.command else {
        panic!("expected login command");
    };
    let context = auth_context(Config {
        auth: AuthConfig {
            method: Some(LoginMethod::Token),
            key: Some("/config-only-key".into()),
            token: Some("toml-token".to_owned()),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    let error = super::login(&context, &args)
        .await
        .expect_err("CLI public-key method overrides TOML and reads CLI key");
    let expected_key = dirs::home_dir()
        .expect("home directory")
        .join("kmesh-login-test-missing-key");
    assert!(format!("{error:#}").contains(&expected_key.display().to_string()));
}

#[tokio::test]
async fn token_env_precedence_child() {
    let Ok(mode) = std::env::var(TOKEN_ENV_CHILD) else {
        return;
    };
    let cli = if mode == "cli" {
        Cli::try_parse_from(["kmesh", "login", "--method", "token", "--token", ""])
    } else {
        Cli::try_parse_from(["kmesh", "login"])
    }
    .expect("parse child login command");
    let ClientCommand::Login(args) = cli.command else {
        panic!("expected login command");
    };
    let context = auth_context(Config {
        auth: AuthConfig {
            method: Some(LoginMethod::Token),
            token: Some("toml-token".to_owned()),
            ..AuthConfig::default()
        },
        ..Config::default()
    })
    .await;
    let error = super::login(&context, &args)
        .await
        .expect_err("empty CLI/environment token overrides TOML");
    assert!(format!("{error:#}").contains("API token is empty"));
}

#[tokio::test]
async fn cli_token_and_environment_override_toml_in_isolated_processes() {
    let executable = std::env::current_exe().expect("resolve auth test executable");
    for (mode, environment_token) in [("cli", "environment-token"), ("environment", "")] {
        let output = Command::new(&executable)
            .args([
                "--exact",
                "client::auth::tests::token_env_precedence_child",
                "--nocapture",
            ])
            .env(TOKEN_ENV_CHILD, mode)
            .env("KMESH_TOKEN", environment_token)
            .output()
            .expect("run token precedence child process");
        assert!(output.status.success(), "token precedence child passed");
    }
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
    assert!(
        request
            .windows(expected_refresh_token.len())
            .any(|window| window == expected_refresh_token.as_bytes()),
        "request contains the saved refresh credential"
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
        let body = serde_json::to_vec(&reply).expect("encode refresh response");
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("write refresh response headers");
        stream
            .write_all(&body)
            .await
            .expect("write refresh response body");
        stream.shutdown().await.expect("close refresh response");
    }
}

async fn one_api_jwt_me_request(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    expected_token: String,
    me: MeView,
) {
    let (socket, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("API JWT validation request arrives")
        .expect("accept API JWT validation request");
    let mut stream = timeout(Duration::from_secs(5), acceptor.accept(socket))
        .await
        .expect("HTTPS handshake completes")
        .expect("accept HTTPS validation request");
    let request = timeout(Duration::from_secs(5), read_http_request(&mut stream))
        .await
        .expect("validation HTTP request completes");
    let request_text = String::from_utf8_lossy(&request);
    assert!(request_text.to_ascii_lowercase().starts_with("get /v1/me "));
    let authorization = request_text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_owned())
        })
        .expect("API JWT validation request includes Authorization");
    assert_eq!(authorization, format!("Bearer {expected_token}"));
    let response = serde_json::to_vec(&me).expect("encode current user");
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write validation response headers");
    stream
        .write_all(&response)
        .await
        .expect("write validation response body");
    stream.shutdown().await.expect("close validation response");
}

#[tokio::test]
async fn api_jwt_login_uses_the_token_directly_and_saves_that_credential() {
    let directory = TestDirectory::new("token-login-test");
    let acceptor = test_tls_acceptor();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind local token login server");
    let server_port = listener.local_addr().unwrap().port();
    let now = unix_now().unwrap();
    let me = MeView {
        user: UserView {
            user_id: "alice".to_owned(),
            username: "Alice".to_owned(),
            enabled: true,
        },
        roles: Vec::new(),
    };
    let claims = crate::protocol::ApiTokenClaims {
        sub: "alice".to_owned(),
        jti: Uuid::new_v4(),
        iss: "https://test.invalid".to_owned(),
        aud: crate::identity::API_TOKEN_AUDIENCE.to_owned(),
        iat: now,
        exp: Some(now + 3600),
    };
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let expected_token = format!("e30.{payload}.signature");
    let server = tokio::spawn(one_api_jwt_me_request(
        listener,
        acceptor,
        expected_token.clone(),
        me,
    ));
    let config = Config {
        server_addr: "127.0.0.1".to_owned(),
        server_port,
        data_dir: directory.0.clone(),
        auth: AuthConfig {
            method: Some(LoginMethod::Token),
            token: Some(expected_token.clone()),
            ..AuthConfig::default()
        },
        ..Config::default()
    };
    let context = auth_context(config).await;

    super::login(&context, &LoginArgs::default())
        .await
        .expect("login with configured API JWT");
    server.await.expect("token login server completes");

    assert_eq!(context.profiles.active_user().unwrap(), "alice");
    let saved = context.profiles.load("alice").unwrap().unwrap();
    assert_eq!(saved.username, "alice");
    assert!(matches!(saved.credential,
        SavedCredential::ApiToken { token, expires_at: Some(exp) }
            if token == expected_token && exp == now + 3600));
}

#[tokio::test]
async fn expired_api_jwt_requires_a_replacement_without_refreshing() {
    let directory = TestDirectory::new("expired-api-jwt-test");
    let config = Config {
        data_dir: directory.0.clone(),
        ..Config::default()
    };
    let context = auth_context(config).await;
    context
        .profiles
        .save(&SavedLogin {
            server_url: context.api.issuer().to_owned(),
            profile: context.config.profile.clone(),
            username: "alice".to_owned(),
            credential: SavedCredential::ApiToken {
                token: "expired.jwt.signature".to_owned(),
                expires_at: Some(unix_now().unwrap() - 1),
            },
        })
        .expect("save expired API JWT");
    context
        .profiles
        .set_active_user("alice")
        .expect("select expired API JWT");

    let error = super::valid_access_token(&context).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "API token expired. Set a new token and run kmesh login."
    );
    assert!(context.profiles.load("alice").unwrap().is_none());
    assert!(context.profiles.active_user().is_err());
}

#[tokio::test]
async fn missing_saved_login_reports_the_login_command() {
    let directory = TestDirectory::new("missing-saved-login-test");
    let context = auth_context(Config {
        data_dir: directory.0.clone(),
        ..Config::default()
    })
    .await;
    let error = super::valid_access_token_for_user(&context, "alice")
        .await
        .expect_err("missing login requires authentication");
    assert_eq!(error.to_string(), "No saved login. Run kmesh login.");
}

#[tokio::test]
async fn expired_public_key_session_reports_the_login_command_and_clears_credentials() {
    let directory = TestDirectory::new("expired-public-key-session-test");
    let context = auth_context(Config {
        data_dir: directory.0.clone(),
        ..Config::default()
    })
    .await;
    let now = unix_now().unwrap();
    context
        .profiles
        .save(&SavedLogin {
            server_url: context.api.issuer().to_owned(),
            profile: context.config.profile.clone(),
            username: "alice".to_owned(),
            credential: SavedCredential::PublicKeySession {
                tokens: LoginTokens {
                    access_token: "expired-access-token".to_owned(),
                    refresh_token: "expired-refresh-token".to_owned(),
                    access_expires_at: now - 1,
                    refresh_expires_at: now - 1,
                },
            },
        })
        .expect("save expired public-key session");
    context
        .profiles
        .set_active_user("alice")
        .expect("select expired public-key session");

    let error = super::valid_access_token(&context)
        .await
        .expect_err("expired public-key session requires authentication");
    assert_eq!(error.to_string(), "Login expired. Run kmesh login.");
    assert!(context.profiles.load("alice").unwrap().is_none());
    assert!(context.profiles.active_user().is_err());
}

#[test]
fn private_key_and_public_key_paths_use_the_same_ssh_signature() {
    let directory = TestDirectory::new("ssh-signing-test");
    let private_key = generate_ssh_key(&directory.0, "id_ed25519");
    let public_key_path = private_key.with_extension("pub");
    let private_public_key =
        public_key(&private_key).expect("extract public key from private file");
    let public_public_key = public_key(&public_key_path).expect("read public key file");
    assert_eq!(private_public_key, public_public_key);

    let payload = b"kmesh SSHSIG signing test payload";
    let signature = sign_sshsig(&private_key, payload).expect("sign challenge with private key");
    let signature = SshSig::from_pem(signature.as_bytes()).expect("parse SSHSIG output");
    let public_key = PublicKey::from_openssh(&public_public_key).expect("parse SSH public key");
    public_key
        .verify("kmesh-login", payload, &signature)
        .expect("verify client SSHSIG output");
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
    let signature =
        SshSig::from_pem(fs::read_to_string(&output_path).expect("read SSH agent signature"))
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
    let output = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_OUTPUT").expect("output file"));
    let ready = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_READY").expect("ready file"));
    let go = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_GO").expect("start gate"));
    let (server_addr, server_port) = server_address_and_port(&server_url);
    let config = Config {
        server_addr,
        server_port,
        data_dir: data_dir.clone(),
        profile: "shared-profile".to_owned(),
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
    let token = super::valid_access_token_for_user(&context, "alice")
        .await
        .expect("obtain concurrently refreshed access token");
    fs::write(output, token).expect("write child refresh result");
}

#[tokio::test]
async fn concurrent_process_refreshes_rotate_once_and_share_saved_credentials() {
    let directory = TestDirectory::new("refresh-process-test");
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
        .save(&SavedLogin {
            server_url: server_url.clone(),
            profile: "shared-profile".to_owned(),
            username: "alice".to_owned(),
            credential: SavedCredential::PublicKeySession {
                tokens: LoginTokens {
                    access_token: "expired-access-token".to_owned(),
                    refresh_token: "old-refresh-token".to_owned(),
                    access_expires_at: now - 1,
                    refresh_expires_at: now + 3600,
                },
            },
        })
        .expect("save expired test login");
    profiles.set_active_user("alice").expect("set active user");

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
    assert!(matches!(saved.credential,
        SavedCredential::PublicKeySession { tokens }
            if tokens.refresh_token == "rotated-refresh-token"));
}

#[tokio::test]
async fn uncertain_refresh_response_clears_saved_login_and_active_user() {
    let directory = TestDirectory::new("uncertain-refresh-test");
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
        .save(&SavedLogin {
            server_url: server_url.clone(),
            profile: "uncertain-profile".to_owned(),
            username: "alice".to_owned(),
            credential: SavedCredential::PublicKeySession {
                tokens: LoginTokens {
                    access_token: "expired-access-token".to_owned(),
                    refresh_token: "unknown-result-refresh-token".to_owned(),
                    access_expires_at: now - 1,
                    refresh_expires_at: now + 3600,
                },
            },
        })
        .expect("save login before uncertain refresh");
    profiles
        .set_active_user("alice")
        .expect("set active user before uncertain refresh");
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
    let config = Config {
        server_addr,
        server_port,
        data_dir: directory.0.clone(),
        profile: "uncertain-profile".to_owned(),
        ..Config::default()
    };
    let api = Api::new(&config).await.expect("build API client");
    let context = ClientContext {
        profiles: ProfileStore::new(
            &config.data_dir,
            &config.server_origin().expect("test server origin"),
            &config.profile,
        ),
        config,
        api,
    };
    let error = super::valid_access_token_for_user(&context, "alice")
        .await
        .expect_err("an uncertain refresh requires authentication");
    assert!(
        format!("{error:#}")
            .contains("Cannot confirm the credential refresh. Run kmesh login again.")
    );
    server
        .await
        .expect("uncertain refresh server task completes");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    assert!(context.profiles.load("alice").unwrap().is_none());
    assert!(context.profiles.active_user().is_err());
}
