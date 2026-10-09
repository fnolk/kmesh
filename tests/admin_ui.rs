//! Exercise the public CLI against a local server, including joined API reads.

use std::{
    fs,
    io::Write,
    net::{TcpListener, TcpStream, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use uuid::Uuid;

struct Fixture {
    directory: PathBuf,
    port: u16,
    api_token: Option<String>,
    server: Option<Child>,
}

impl Fixture {
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kmesh"));
        command
            .arg("-c")
            .arg(self.directory.join("config.toml"))
            .arg("-d")
            .arg(self.directory.join("state"))
            .args(["-s", "127.0.0.1", "-P", &self.port.to_string()])
            .env_remove("RUST_LOG");
        if let Some(token) = &self.api_token {
            command.env("KMESH_TOKEN", token);
        } else {
            command.env_remove("KMESH_TOKEN");
        }
        command
    }

    fn command_with_token(&self, token: &str) -> Command {
        let mut command = self.command();
        command.env("KMESH_TOKEN", token);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("run test CLI")
    }

    fn success(&self, args: &[&str]) -> String {
        let output = self.run(args);
        // Do not include stdout in errors: token creation returns a secret there.
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8 CLI output")
    }

    fn success_with_token(&self, token: &str, args: &[&str]) -> String {
        let output = self.command_with_token(token).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8 CLI output")
    }

    fn run_with_token(&self, token: &str, args: &[&str]) -> Output {
        self.command_with_token(token)
            .args(args)
            .output()
            .expect("run test CLI with token")
    }

    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.success(args)).expect("one JSON response without a banner")
    }

    fn start() -> Self {
        Self::start_with_relay(false)
    }

    fn start_with_relay(private_relay: bool) -> Self {
        let directory = std::env::temp_dir().join(format!("kmesh-admin-ui-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("config.toml"),
            "[auth]\nmethod = \"token\"\n",
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        drop(udp);
        let mut fixture = Self {
            directory,
            port,
            api_token: None,
            server: None,
        };
        let initialized = fixture.success(&["server", "init", "-a", "root"]);
        let token = initialized
            .lines()
            .last()
            .unwrap()
            .split_once(": ")
            .unwrap()
            .1;
        fixture.api_token = Some(token.to_owned());
        let child = fixture
            .command()
            .args([
                "server",
                "run",
                "--bind-addr",
                "127.0.0.1",
                "--udp-port",
                &udp_port.to_string(),
            ])
            .args(if private_relay {
                vec![]
            } else {
                vec!["--disable-private-relay"]
            })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        fixture.server = Some(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "local admin test server did not start"
            );
            assert!(
                fixture
                    .server
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "local admin test server stopped"
            );
            thread::sleep(Duration::from_millis(25));
        }
        fixture
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = self.server.as_mut() {
            let _ = server.kill();
            let _ = server.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn short_admin_workflow_joins_credentials_and_access_without_secrets() {
    let fixture = Fixture::start();
    fixture.success(&["a", "u", "c", "alice"]);
    fixture.success(&["a", "g", "c", "dev"]);
    let created_target = fixture.json(&["a", "t", "c", "build", "-j"]);
    let enrollment = created_target["data"]["enrollment_token"].as_str().unwrap();
    fixture.success(&["a", "u", "groups", "alice", "dev"]);
    fixture.success(&["a", "gr", "a", "dev", "build"]);
    let created_token = fixture.json(&["a", "tk", "c", "alice", "-l", "laptop", "-e", "600", "-j"]);
    let secret = created_token["data"]["token"].as_str().unwrap();
    let public_key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
    let key_path = fixture.directory.join("id_ed25519.pub");
    fs::write(&key_path, public_key).unwrap();
    fixture.success(&[
        "a",
        "k",
        "a",
        "alice",
        key_path.to_str().unwrap(),
        "-l",
        "work",
    ]);

    let text = fixture.success(&["a", "ls"]);
    for heading in [
        "Admin overview",
        "Users (2)",
        "Access groups (1)",
        "Targets (1)",
        "REGISTERED KEYS",
    ] {
        assert!(text.contains(heading), "missing {heading}");
    }
    assert!(!text.contains('\t'));
    assert!(!text.contains(secret));
    assert!(!text.contains(enrollment));
    let detail = fixture.json(&["a", "u", "s", " ALICE ", "-j"]);
    assert_eq!(
        detail["users"][0]["authorized_target_ids"],
        serde_json::json!(["build"])
    );
    assert_eq!(detail["users"][0]["system_role"], "member");
    assert_eq!(
        detail["users"][0]["access_groups"],
        serde_json::json!(["dev"])
    );
    assert_eq!(detail["users"][0]["active_token_count"], 1);
    assert_eq!(detail["users"][0]["key_count"], 1);
    assert_eq!(detail["access_paths"][0]["authorized"], true);
    assert_eq!(detail["access_paths"][0]["online"], false);
    assert!(
        detail["keys"][0]["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
    let serialized = detail.to_string();
    assert!(!serialized.contains(secret));
    assert!(!serialized.contains(enrollment));
    assert!(!serialized.contains(public_key));
    assert_eq!(
        fixture.json(&["admin", "keys", "list", "alice", "--json"])["result"],
        "keys"
    );
    assert_eq!(
        fixture.json(&["admin", "--json"])["selection"]["kind"],
        "overview"
    );

    fixture.success(&["a", "u", "off", "alice"]);
    let detail = fixture.json(&["a", "t", "s", "build", "-j"]);
    assert_eq!(detail["access_paths"][0]["authorized"], false);
    assert_eq!(
        detail["access_paths"][0]["blockers"],
        serde_json::json!(["user_disabled"])
    );
    let missing = fixture.run(&["a", "r", "s", "missing"]);
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());

    // The server retains grants after a soft deletion; the overview must still work.
    fixture.success(&["a", "t", "rm", "build"]);
    let after_delete = fixture.json(&["a", "ls", "-j"]);
    assert_eq!(
        after_delete["targets"][0]["available_in_target_list"],
        false
    );
    assert!(after_delete["targets"][0]["enabled"].is_null());
    assert_eq!(
        after_delete["targets"][0]["authorized_user_ids"],
        serde_json::json!([])
    );
    assert!(!after_delete["warnings"].as_array().unwrap().is_empty());
    let alice = after_delete["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["user_id"] == "alice")
        .unwrap();
    assert_eq!(alice["authorized_target_ids"], serde_json::json!([]));
}

#[test]
fn member_cannot_enter_any_admin_cli_mode() {
    let fixture = Fixture::start();
    fixture.success(&["admin", "users", "create", "member"]);
    let issued = fixture.json(&[
        "admin", "tokens", "create", "member", "--label", "cli-test", "--json",
    ]);
    let member_token = issued["data"]["token"].as_str().unwrap();
    let status = fixture.success_with_token(member_token, &["--profile", "member", "status", "-j"]);
    assert!(!status.contains(member_token));
    let status: Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status["user"], "member");
    let hidden = fixture.run_with_token(
        member_token,
        &["--profile", "member", "doctor", "hidden", "-j"],
    );
    assert!(!hidden.status.success());
    let hidden: Value = serde_json::from_slice(&hidden.stdout).unwrap();
    assert!(
        hidden["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["stage"] == "access" && c["status"] == "failed")
    );

    for args in [
        vec!["--profile", "member", "admin"],
        vec!["--profile", "member", "admin", "users", "list"],
        vec!["--profile", "member", "admin", "--json"],
        vec!["--profile", "member", "a", "u", "ls"],
        vec!["--profile", "member", "access", "explain", "root", "hidden"],
        vec![
            "--profile",
            "member",
            "a",
            "u",
            "add-groups",
            "member",
            "dev",
        ],
    ] {
        let output = fixture.run_with_token(member_token, &args);
        assert!(!output.status.success(), "{args:?} entered admin mode");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("does not have the admin platform role"),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn admin_shell_shows_identity_and_exits_after_role_revocation() {
    let fixture = Fixture::start();
    fixture.success(&["admin", "users", "create", "operator"]);
    let issued = fixture.json(&[
        "admin",
        "tokens",
        "create",
        "operator",
        "--label",
        "shell-test",
        "--json",
    ]);
    let operator_token = issued["data"]["token"].as_str().unwrap();
    fixture.success(&["admin", "users", "roles", "operator", "admin"]);
    let mut command = fixture.command_with_token(operator_token);
    command
        .args(["admin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut shell = command.spawn().expect("start admin shell");
    shell
        .stdin
        .take()
        .expect("open admin shell input")
        .write_all(b"users roles operator member\nusers list\nusers create must-not-run\n")
        .expect("send shell commands");
    let output = shell.wait_with_output().expect("wait for admin shell");
    assert!(
        !output.status.success(),
        "shell exited with success; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("read shell output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Server: https://127.0.0.1:"));
    assert!(stdout.contains("User: operator"));
    assert!(stdout.contains("Platform role: admin"));
    assert!(stderr.contains("Admin access was revoked. The shell is closed."));
    assert!(!stdout.contains("must-not-run"));

    let users = fixture.json(&["admin", "users", "list", "--json"]);
    assert!(
        !users["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|user| user["user_id"] == "must-not-run")
    );
}

#[test]
fn group_changes_preview_impacts_and_require_explicit_clear() {
    let f = Fixture::start();
    f.success(&["a", "u", "c", "alice"]);
    for group in ["dev", "ops"] {
        f.success(&["a", "g", "c", group]);
    }
    f.success(&["a", "t", "c", "build"]);
    for group in ["dev", "ops"] {
        f.success(&["a", "gr", "a", group, "build"]);
    }
    let set = f.json(&["a", "u", "groups", "alice", "dev", "-j"]);
    assert_eq!(set["result"], "user_access_groups");
    assert_eq!(set["data"][0]["group_id"], "dev");
    let add = f.json(&["a", "u", "add-groups", " ALICE ", " OPS ", "ops", "-j"]);
    assert_eq!(
        add["data"]["change"]["after"],
        serde_json::json!(["dev", "ops"])
    );
    let remove = f.json(&["a", "u", "remove-groups", "alice", "dev", "-j"]);
    assert_eq!(
        remove["data"]["change"]["lost_target_ids"],
        serde_json::json!([])
    );
    let preview = f.json(&["a", "u", "groups", "alice", "--dry-run", "-j"]);
    assert_eq!(preview["data"]["applied"], false);
    assert_eq!(
        preview["data"]["change"]["lost_target_ids"],
        serde_json::json!(["build"])
    );
    for args in [
        vec!["a", "u", "groups", "alice"],
        vec!["a", "u", "remove-groups", "alice", "ops", "-j"],
    ] {
        let output = f.run(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--yes"));
    }
    assert_eq!(
        f.json(&["a", "u", "show-groups", "alice", "-j"])["data"][0]["group_id"],
        "ops"
    );
    let invalid = f.run(&["a", "u", "add-groups", "alice", "missing"]);
    assert!(!invalid.status.success());
    let clear = f.json(&["a", "u", "groups", "alice", "--yes", "-j"]);
    assert_eq!(clear["data"], serde_json::json!([]));
    assert_eq!(
        clear["change"]["lost_target_ids"],
        serde_json::json!(["build"])
    );
}

#[test]
fn diagnostics_distinguish_authorization_offline_and_credential_failures() {
    let f = Fixture::start();
    let status = f.json(&["status", "-j"]);
    assert_eq!(status["user"], "root");
    assert!(
        status["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["status"] == "passed")
    );
    f.success(&["a", "t", "c", "build"]);
    let denied = f.json(&["access", "explain", "root", "build", "-j"]);
    assert_eq!(denied["authorized"], false);
    assert_eq!(
        denied["blockers"],
        serde_json::json!(["no_access_groups", "no_ssh_connect_grant"])
    );
    f.success(&["a", "g", "c", "dev"]);
    f.success(&["a", "u", "add-groups", "root", "dev"]);
    f.success(&["a", "gr", "a", "dev", "build"]);
    let granted = f.json(&["access", "explain", "ROOT", "BUILD", "-j"]);
    assert_eq!(granted["authorized"], true);
    assert_eq!(granted["online"], false);
    let offline = f.run(&["doctor", "build", "-j"]);
    assert!(!offline.status.success());
    let report: Value = serde_json::from_slice(&offline.stdout).unwrap();
    let checks = report["checks"].as_array().unwrap();
    assert!(
        checks
            .iter()
            .any(|c| c["stage"] == "agent" && c["status"] == "failed")
    );
    assert!(
        checks
            .iter()
            .any(|c| c["stage"] == "sshd" && c["status"] == "not_checked")
    );
    f.success(&["a", "t", "off", "build"]);
    let disabled = f.json(&["access", "explain", "root", "build", "-j"]);
    assert_eq!(disabled["blockers"], serde_json::json!(["target_disabled"]));
    f.success(&["a", "t", "rm", "build"]);
    let missing = f.json(&["access", "explain", "root", "build", "-j"]);
    assert_eq!(
        missing["blockers"],
        serde_json::json!(["target_unavailable"])
    );
    let invalid = f
        .command_with_token("invalid-api-token")
        .args(["status", "-j"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    let report: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["stage"] == "credentials" && c["status"] == "failed")
    );
}

struct AgentProcess(Child);
impl Drop for AgentProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn doctor_checks_a_real_agent_and_ssh_identification_without_authentication() {
    use std::io::Read;
    let f = Fixture::start_with_relay(true);
    let ssh = TcpListener::bind("127.0.0.1:0").unwrap();
    let ssh_address = ssh.local_addr().unwrap();
    ssh.set_nonblocking(true).unwrap();
    let stub = thread::spawn(move || {
        for banner in ["SSH-2.0-kmesh-test\r\n", "HTTP/1.1 200 OK\r\n"] {
            let deadline = Instant::now() + Duration::from_secs(90);
            let mut connection = loop {
                match ssh.accept() {
                    Ok((connection, _)) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "doctor did not reach the SSH stub"
                        );
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("SSH stub failed: {error}"),
                }
            };
            connection.write_all(banner.as_bytes()).unwrap();
            connection.shutdown(std::net::Shutdown::Write).unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut received = Vec::new();
            let _ = connection.read_to_end(&mut received);
            assert!(
                received.is_empty(),
                "doctor must not send SSH authentication or commands"
            );
        }
    });
    let created = f.json(&["a", "t", "c", "probe", "-j"]);
    let enrollment = created["data"]["enrollment_token"].as_str().unwrap();
    let agent_command = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kmesh"));
        c.args(["-s", "127.0.0.1", "-P", &f.port.to_string(), "-d"])
            .arg(f.directory.join("agent"))
            .env_remove("KMESH_TOKEN")
            .env_remove("RUST_LOG");
        c
    };
    let enroll = agent_command()
        .args([
            "agent",
            "enroll",
            "-t",
            "probe",
            "-e",
            enrollment,
            "--ssh-address",
            &ssh_address.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        enroll.status.success(),
        "{}",
        String::from_utf8_lossy(&enroll.stderr)
    );
    let mut agent = AgentProcess(
        Command::new(env!("CARGO_BIN_EXE_kmesh"))
            .arg("-d")
            .arg(f.directory.join("agent"))
            .args(["agent", "run", "-t", "probe"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    f.success(&["a", "g", "c", "probe"]);
    f.success(&["a", "u", "add-groups", "root", "probe"]);
    f.success(&["a", "gr", "a", "probe", "probe"]);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let view = f.json(&["access", "explain", "root", "probe", "-j"]);
        if view["online"] == true {
            break;
        }
        assert!(agent.0.try_wait().unwrap().is_none(), "agent stopped");
        assert!(Instant::now() < deadline, "agent did not connect");
        thread::sleep(Duration::from_millis(50));
    }
    let healthy = f.json(&["doctor", "probe", "-j"]);
    assert!(
        healthy["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["stage"] == "sshd" && c["status"] == "passed")
    );
    let invalid = f.run(&["doctor", "probe", "-j"]);
    assert!(!invalid.status.success());
    let report: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["stage"] == "network" && c["status"] == "passed")
    );
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["stage"] == "sshd" && c["status"] == "failed")
    );
    stub.join().unwrap();
}
