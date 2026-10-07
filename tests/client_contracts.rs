use std::process::Command;

use clap::Parser;
use kmesh::{
    client::{Cli, ssh_config},
    protocol::TargetView,
};
use uuid::Uuid;

#[test]
fn cli_help_and_global_data_directory_parse_after_subcommand() {
    let binary = env!("CARGO_BIN_EXE_kmesh");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.starts_with("SSH access over direct QUIC or relay"));
    assert!(help.contains("Print an OpenSSH configuration entry for a target"));
    assert!(help.contains("Open an SSH stream to a target"));
    assert!(help.contains("--server-addr"));
    assert!(help.contains("--server-port"));
    assert!(help.contains("~/.kmesh/config.toml"));
    assert!(help.contains("~/.cache/kmesh"));
    assert!(!help.contains("--server-url"));

    let server_help = Command::new(binary)
        .args(["server", "init", "--help"])
        .output()
        .unwrap();
    assert!(server_help.status.success());
    let server_help = String::from_utf8(server_help.stdout).unwrap();
    assert!(server_help.contains("--data-dir <DATA_DIR>"));
    assert!(server_help.contains("Usage: kmesh server init"));
    assert!(server_help.contains("Initialize server data and create the first administrator"));
    assert!(!server_help.contains("--issuer"));
}

#[test]
fn agent_enrollment_accepts_url_safe_tokens_starting_with_a_dash() {
    let target_id = Uuid::new_v4().to_string();
    let args = [
        "kmesh",
        "agent",
        "enroll",
        "--target-id",
        &target_id,
        "--enrollment-code",
        "-one-time-token",
    ];
    assert!(kmesh::client::Cli::try_parse_from(args).is_ok());
}

#[test]
fn cli_splits_server_address_and_ports_and_removes_server_url() {
    let target_id = Uuid::new_v4().to_string();
    let cli = Cli::try_parse_from([
        "kmesh",
        "--server-addr",
        "2001:db8::1",
        "--server-port",
        "9555",
        "proxy",
        &target_id,
    ])
    .expect("parse split server address and port");
    assert_eq!(cli.server_addr.as_deref(), Some("2001:db8::1"));
    assert_eq!(cli.server_port, Some(9555));
    assert!(
        Cli::try_parse_from([
            "kmesh",
            "--server-url",
            "https://example.test",
            "proxy",
            &target_id,
        ])
        .is_err()
    );

    assert!(
        Cli::try_parse_from([
            "kmesh",
            "server",
            "run",
            "--udp-port",
            "4000",
            "--disable-private-relay=false",
        ])
        .is_ok()
    );
}

#[test]
fn cli_accepts_token_and_public_key_login_inputs() {
    let cli = Cli::try_parse_from([
        "kmesh",
        "login",
        "--method",
        "public-key",
        "--username",
        "alice",
        "--key",
        "~/.ssh/id_ed25519",
    ])
    .expect("parse public-key login overrides");
    let kmesh::client::Command::Login(args) = cli.command else {
        panic!("expected login command");
    };
    assert_eq!(args.method, Some(kmesh::config::LoginMethod::PublicKey));
    assert_eq!(args.username.as_deref(), Some("alice"));
    assert_eq!(
        args.key.as_deref(),
        Some(std::path::Path::new("~/.ssh/id_ed25519"))
    );

    let cli = Cli::try_parse_from([
        "kmesh",
        "login",
        "--method",
        "token",
        "--token",
        "kmesh_opaque_token",
    ])
    .expect("parse token login override");
    let kmesh::client::Command::Login(args) = cli.command else {
        panic!("expected login command");
    };
    assert_eq!(args.method, Some(kmesh::config::LoginMethod::Token));
    assert_eq!(args.token.as_deref(), Some("kmesh_opaque_token"));
    assert!(Cli::try_parse_from(["kmesh", "login", "--password-stdin"]).is_err());
}

#[test]
fn admin_token_commands_parse_and_password_user_commands_are_gone() {
    let user_id = Uuid::new_v4().to_string();
    let token_id = Uuid::new_v4().to_string();
    assert!(
        Cli::try_parse_from([
            "kmesh", "admin", "tokens", "create", &user_id, "--label", "laptop",
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["kmesh", "admin", "tokens", "list", &user_id]).is_ok());
    assert!(Cli::try_parse_from(["kmesh", "admin", "tokens", "revoke", &token_id]).is_ok());
    assert!(Cli::try_parse_from(["kmesh", "admin", "users", "create", "alice"]).is_ok());
    assert!(Cli::try_parse_from(["kmesh", "admin", "users", "reset-password", &user_id]).is_err());
}

#[test]
fn admin_key_registration_takes_a_public_key_file() {
    let user_id = Uuid::new_v4().to_string();
    let args = [
        "kmesh",
        "admin",
        "keys",
        "add",
        &user_id,
        "~/.ssh/id_ed25519.pub",
    ];
    assert!(kmesh::client::Cli::try_parse_from(args).is_ok());
}

#[test]
fn ssh_config_uses_stable_alias_and_shell_safe_proxy_arguments() {
    let target_id = Uuid::new_v4();
    let target = TargetView {
        target_id,
        name: "-unsafe\nProxyCommand evil".to_owned(),
        enabled: false,
        online: true,
    };
    let rendered = ssh_config::render(
        &target,
        &Cli::try_parse_from(["kmesh", "ssh-config", &target_id.to_string()]).unwrap(),
    )
    .unwrap();
    assert!(rendered.starts_with(&format!("Host {target_id}\n")));
    assert_eq!(rendered.matches("\nHost ").count(), 0);
    assert!(rendered.contains(&format!("ProxyCommand kmesh proxy {target_id}\n")));
    assert!(!rendered.contains("--config"));
    assert!(!rendered.contains("--data-dir"));
    assert!(!rendered.contains("--profile"));
    assert!(rendered.contains(&format!("HostKeyAlias kmesh/{target_id}")));
}

#[test]
fn ssh_config_replays_only_explicit_overrides_with_absolute_paths() {
    let target_id = Uuid::new_v4();
    let target = TargetView {
        target_id,
        name: "build-machine".to_owned(),
        enabled: true,
        online: true,
    };
    let cli = Cli::try_parse_from([
        "kmesh",
        "--config",
        "config with %tokens.toml",
        "--data-dir",
        "kmesh %home",
        "--profile",
        "%h-profile",
        "--server-addr",
        "example.test",
        "--server-port",
        "9555",
        "ssh-config",
        &target_id.to_string(),
    ])
    .unwrap();

    let rendered = ssh_config::render(&target, &cli).unwrap();
    let current_dir = std::env::current_dir().unwrap();
    let config_path = current_dir.join("config with %tokens.toml");
    let data_dir = current_dir.join("kmesh %home");
    assert!(rendered.contains(&format!(
        "--config '{}'",
        config_path.to_string_lossy().replace('%', "%%")
    )));
    assert!(rendered.contains(&format!(
        "--data-dir '{}'",
        data_dir.to_string_lossy().replace('%', "%%")
    )));
    assert!(rendered.contains("--profile '%%h-profile'"));
    assert!(rendered.contains("--server-addr 'example.test'"));
    assert!(rendered.contains("--server-port 9555"));
    assert!(rendered.contains(&format!("proxy {target_id}")));
}

#[test]
fn client_server_origin_requires_https_and_normalizes_default_port() {
    assert_eq!(
        kmesh::client::canonical_origin("https://example.test:443/").unwrap(),
        "https://example.test"
    );
    assert!(kmesh::client::canonical_origin("http://example.test").is_err());
    assert!(kmesh::client::canonical_origin("https://example.test/path").is_err());
}
