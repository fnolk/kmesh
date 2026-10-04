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

use rustls::pki_types::PrivateKeyDer;
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
        ClientContext,
        api::Api,
        profile::{ProfileStore, SavedLogin},
    },
    config::{Config, TlsConfig},
    protocol::LoginTokens,
};

use super::*;

const REFRESH_CHILD_ENV: &str = "KMESH_TEST_REFRESH_CHILD";
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

fn test_tls_acceptor(directory: &Path) -> (TlsAcceptor, PathBuf) {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("generate local test certificate");
    let cert_pem = certificate.cert.pem();
    let key_pem = certificate.signing_key.serialize_pem();
    let ca_path = directory.join("test-ca.pem");
    fs::write(&ca_path, cert_pem.as_bytes()).expect("write local CA certificate");
    let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("parse local certificate");
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
            .expect("parse local private key")
            .expect("local certificate has a private key");
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("build local HTTPS server config");
    (TlsAcceptor::from(Arc::new(config)), ca_path)
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
    let ca_file = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_CA").expect("CA file"));
    let output = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_OUTPUT").expect("output file"));
    let ready = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_READY").expect("ready file"));
    let go = PathBuf::from(std::env::var_os("KMESH_TEST_REFRESH_GO").expect("start gate"));
    let config = Config {
        server_url,
        data_dir: data_dir.clone(),
        profile: "shared-profile".to_owned(),
        tls: TlsConfig {
            ca_certificates: vec![ca_file],
            server_name: None,
            proxy: None,
        },
        ..Config::default()
    };
    let api = Api::new(&config).await.expect("build API client");
    let profiles = ProfileStore::new(&config.data_dir, &config.server_url, &config.profile);
    let context = ClientContext {
        config,
        config_path: None,
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
    let (acceptor, ca_file) = test_tls_acceptor(&directory.0);
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
            tokens: LoginTokens {
                access_token: "expired-access-token".to_owned(),
                refresh_token: "old-refresh-token".to_owned(),
                access_expires_at: now - 1,
                refresh_expires_at: now + 3600,
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
        .env("KMESH_TEST_REFRESH_CA", &ca_file)
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
        .env("KMESH_TEST_REFRESH_CA", &ca_file)
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
async fn uncertain_refresh_response_clears_saved_login_and_active_user() {
    let directory = TestDirectory::new("uncertain-refresh-test");
    let (acceptor, ca_file) = test_tls_acceptor(&directory.0);
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
            tokens: LoginTokens {
                access_token: "expired-access-token".to_owned(),
                refresh_token: "unknown-result-refresh-token".to_owned(),
                access_expires_at: now - 1,
                refresh_expires_at: now + 3600,
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

    let config = Config {
        server_url: server_url.clone(),
        data_dir: directory.0.clone(),
        profile: "uncertain-profile".to_owned(),
        tls: TlsConfig {
            ca_certificates: vec![ca_file],
            server_name: None,
            proxy: None,
        },
        ..Config::default()
    };
    let api = Api::new(&config).await.expect("build API client");
    let context = ClientContext {
        profiles: ProfileStore::new(&config.data_dir, &config.server_url, &config.profile),
        config,
        config_path: None,
        api,
    };
    assert!(
        super::valid_access_token_for_user(&context, "alice")
            .await
            .is_err()
    );
    server
        .await
        .expect("uncertain refresh server task completes");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    assert!(context.profiles.load("alice").unwrap().is_none());
    assert!(context.profiles.active_user().is_err());
}
