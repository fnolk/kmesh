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
    assert!(help.contains("Set the base directory for local or server data."));
    assert!(!help.contains("~/.cache/kmesh"));
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
    let target_id = "build-machine".to_owned();
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

#[cfg(unix)]
#[test]
fn agent_commands_use_data_dir_and_ignore_the_default_config_file() {
    use std::fs;

    let root = std::env::temp_dir().join(format!("kmesh-agent-cli-{}", Uuid::new_v4()));
    let home = root.join("home");
    let data_dir = root.join("agent state");
    fs::create_dir_all(home.join(".kmesh")).unwrap();
    fs::write(home.join(".kmesh/config.toml"), "invalid = [\n").unwrap();
    let binary = env!("CARGO_BIN_EXE_kmesh");
    let data_dir_text = data_dir.to_str().unwrap();

    let run = Command::new(binary)
        .env("HOME", &home)
        .args([
            "--data-dir",
            data_dir_text,
            "agent",
            "run",
            "--target-id",
            "build-machine",
        ])
        .output()
        .unwrap();
    assert!(!run.status.success());
    let stderr = String::from_utf8(run.stderr).unwrap();
    assert!(stderr.contains("Run `agent enroll`"), "{stderr}");
    assert!(!stderr.contains("config.toml"), "{stderr}");
    assert!(data_dir_text.contains("agent state"));

    let enroll = Command::new(binary)
        .env("HOME", &home)
        .args([
            "--data-dir",
            data_dir_text,
            "--server-addr",
            "mesh.example.com",
            "--server-port",
            "0",
            "agent",
            "enroll",
            "--target-id",
            "build-machine",
            "--enrollment-code",
            "test-code",
        ])
        .output()
        .unwrap();
    assert!(!enroll.status.success());
    let stderr = String::from_utf8(enroll.stderr).unwrap();
    assert!(
        stderr.contains("Use a server port from 1 to 65535."),
        "{stderr}"
    );
    assert!(!stderr.contains("config.toml"), "{stderr}");
    assert!(data_dir.exists());

    let config_path = home.join(".kmesh/config.toml");
    let config_path_text = config_path.to_str().unwrap();
    for (options, expected) in [
        (&["--config", config_path_text][..], "Remove --config"),
        (&["--profile", "work"][..], "Remove --profile"),
        (
            &["--server-addr", "mesh.example.com", "--server-port", "9555"][..],
            "saved server settings",
        ),
    ] {
        let mut args = vec!["--data-dir", data_dir_text];
        args.extend_from_slice(options);
        args.extend_from_slice(&["agent", "run", "--target-id", "build-machine"]);
        let output = Command::new(binary)
            .env("HOME", &home)
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains("parse configuration"), "{stderr}");
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_splits_server_address_and_ports_and_removes_server_url() {
    let target_id = "build-machine".to_owned();
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
fn cli_has_no_separate_login_or_logout_commands() {
    assert!(Cli::try_parse_from(["kmesh", "login"]).is_err());
    assert!(Cli::try_parse_from(["kmesh", "logout"]).is_err());
}

#[test]
fn admin_token_commands_parse_and_password_user_commands_are_gone() {
    let user_id = "alice".to_owned();
    let token_id = Uuid::new_v4().to_string();
    assert!(
        Cli::try_parse_from([
            "kmesh", "admin", "tokens", "create", &user_id, "--label", "laptop",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "kmesh",
            "admin",
            "tokens",
            "create",
            &user_id,
            "--label",
            "automation",
            "--expires-in",
            "604800",
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
    let user_id = "alice".to_owned();
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
    let target_id = "build-machine-id".to_owned();
    let target = TargetView {
        target_id: target_id.clone(),
        name: "Build-Machine".to_owned(),
        enabled: false,
        online: true,
    };
    let rendered = ssh_config::render(
        &target,
        &Cli::try_parse_from(["kmesh", "ssh-config", &target_id]).unwrap(),
        "https://one.example:9443",
    )
    .unwrap();
    assert!(rendered.starts_with("Host Build-Machine\n"));
    assert!(rendered.contains(&format!("ProxyCommand kmesh proxy {target_id}\n")));
    assert!(!rendered.contains("--config"));
    assert!(!rendered.contains("--data-dir"));
    assert!(!rendered.contains("--profile"));
    assert!(!rendered.contains("--token"));
    let host_key_alias = rendered
        .lines()
        .find_map(|line| line.strip_prefix("    HostKeyAlias "))
        .expect("rendered SSH config has a host-key alias");
    assert!(host_key_alias.starts_with("kmesh/"));
    assert!(host_key_alias.ends_with(&format!("/{target_id}")));
}

#[test]
fn ssh_config_scopes_host_keys_by_server_origin() {
    let target = TargetView {
        target_id: "office-ssh".to_owned(),
        name: "Office-SSH".to_owned(),
        enabled: true,
        online: true,
    };
    let cli = Cli::try_parse_from(["kmesh", "ssh-config", "office-ssh"]).unwrap();
    let alias = |origin| {
        ssh_config::render(&target, &cli, origin)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("    HostKeyAlias "))
            .unwrap()
            .to_owned()
    };
    let first = alias("https://one.example:9443");
    let second = alias("https://two.example:9443");
    assert_ne!(first, second);
    assert!(first.ends_with("/office-ssh"));
    assert!(second.ends_with("/office-ssh"));
}

#[test]
fn ssh_config_selects_by_normalized_id_when_a_name_matches_another_id() {
    let targets = vec![
        TargetView {
            target_id: "first".to_owned(),
            name: "second".to_owned(),
            enabled: true,
            online: true,
        },
        TargetView {
            target_id: "second".to_owned(),
            name: "First".to_owned(),
            enabled: true,
            online: true,
        },
    ];

    assert_eq!(
        ssh_config::find_target(&targets, " FIRST ")
            .unwrap()
            .target_id,
        "first"
    );
    let selected = ssh_config::find_target(&targets, "second").unwrap();
    assert_eq!(selected.target_id, "second");
    assert_eq!(selected.name, "First");
}

#[test]
fn ssh_config_replays_only_explicit_overrides_with_absolute_paths() {
    let target_id = "build-machine".to_owned();
    let target = TargetView {
        target_id: target_id.clone(),
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
        &target_id,
    ])
    .unwrap();

    let rendered = ssh_config::render(&target, &cli, "https://example.test:9555").unwrap();
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
