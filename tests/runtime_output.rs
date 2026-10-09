use std::{fs, path::PathBuf, process::Command};

use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("kmesh-runtime-output-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create runtime output test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn command_errors_use_english_and_leave_stdout_empty() {
    let directory = TestDirectory::new();
    let missing_config = directory.0.join("missing.toml");
    for arguments in [vec!["status"], vec!["proxy", "build-machine"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_kmesh"))
            .arg("--config")
            .arg(&missing_config)
            .args(arguments)
            .env_remove("RUST_LOG")
            .output()
            .expect("run command with missing configuration");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty(), "errors must not use stdout");
        let stderr = String::from_utf8(output.stderr).expect("decode runtime error");
        assert!(stderr.starts_with("Command failed: configuration file does not exist: "));
        assert!(stderr.contains(&missing_config.display().to_string()));
    }
}

#[test]
fn command_errors_escape_terminal_controls() {
    let directory = TestDirectory::new();
    let missing_config = directory.0.join("missing\n\x1b[31m\u{202e}.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_kmesh"))
        .arg("--config")
        .arg(missing_config)
        .arg("status")
        .env_remove("RUST_LOG")
        .output()
        .expect("run command with control characters in its configuration path");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("decode escaped error");
    assert_eq!(stderr.lines().count(), 1);
    assert!(stderr.contains("missing\\n\\u{1b}[31m\\u{202e}.toml"));
    assert!(!stderr.contains('\x1b'));
    assert!(!stderr.contains('\u{202e}'));
}

#[test]
fn configured_token_validation_uses_english_and_leaves_stdout_empty() {
    let directory = TestDirectory::new();
    let config = directory.0.join("config.toml");
    fs::write(&config, "[auth]\nmethod = \"token\"\ntoken = \"\"\n")
        .expect("write test configuration with an empty token");
    let output = Command::new(env!("CARGO_BIN_EXE_kmesh"))
        .arg("--config")
        .arg(&config)
        .arg("--data-dir")
        .arg(directory.0.join("state"))
        .args(["targets", "list"])
        .env_remove("KMESH_TOKEN")
        .env_remove("RUST_LOG")
        .output()
        .expect("run a command with an empty configured token");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "errors must not use stdout");
    assert_eq!(
        String::from_utf8(output.stderr).expect("decode token error"),
        "Command failed: API token is empty\n"
    );
}

#[test]
fn server_initialization_reports_english_success_and_token_labels() {
    let directory = TestDirectory::new();
    let config = directory.0.join("config.toml");
    fs::write(&config, "").expect("write default test configuration");
    let output = Command::new(env!("CARGO_BIN_EXE_kmesh"))
        .arg("--config")
        .arg(&config)
        .arg("--data-dir")
        .arg(directory.0.join("state"))
        .args(["server", "init", "--admin", "alice"])
        .env_remove("RUST_LOG")
        .output()
        .expect("initialize a test server");
    assert!(
        output.status.success(),
        "server initialization must succeed"
    );
    let stdout = String::from_utf8(output.stdout).expect("decode initialization output");
    assert!(stdout.starts_with("Server initialized. issuer=https://localhost:9443\n"));
    assert!(stdout.contains("Initial administrator API token (shown once): "));
}
