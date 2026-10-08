//! Exercise the public CLI against a local server, including joined API reads.

use std::{
    fs,
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
            .env_remove("KMESH_TOKEN")
            .env_remove("RUST_LOG");
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

    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.success(args)).expect("one JSON response without a banner")
    }

    fn start() -> Self {
        let directory = std::env::temp_dir().join(format!("kmesh-admin-ui-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("config.toml"), "").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        drop(udp);
        let mut fixture = Self {
            directory,
            port,
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
        let child = fixture
            .command()
            .args([
                "server",
                "run",
                "--bind-addr",
                "127.0.0.1",
                "--udp-port",
                &udp_port.to_string(),
                "--disable-private-relay",
            ])
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
        let login = fixture
            .command()
            .args(["login", "-m", "token"])
            .env("KMESH_TOKEN", token)
            .output()
            .unwrap();
        assert!(
            login.status.success(),
            "local login failed: {}",
            String::from_utf8_lossy(&login.stderr)
        );
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
    fixture.success(&["a", "r", "c", "dev"]);
    let created_target = fixture.json(&["a", "t", "c", "build", "-j"]);
    let enrollment = created_target["data"]["enrollment_token"].as_str().unwrap();
    fixture.success(&["a", "u", "roles", "alice", "dev"]);
    fixture.success(&["a", "g", "a", "dev", "build"]);
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
        "Roles (2)",
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
