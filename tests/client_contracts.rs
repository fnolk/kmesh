use std::process::Command;

use clap::Parser;
use kmesh::{client::ssh_config, config::Config, protocol::TargetView};
use uuid::Uuid;

#[test]
fn cli_help_and_global_data_directory_parse_after_subcommand() {
    let binary = env!("CARGO_BIN_EXE_kmesh");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.starts_with("kmesh"));
    assert!(help.contains("ssh-config"));
    assert!(help.contains("proxy"));

    let server_help = Command::new(binary)
        .args(["server", "init", "--help"])
        .output()
        .unwrap();
    assert!(server_help.status.success());
    let server_help = String::from_utf8(server_help.stdout).unwrap();
    assert!(server_help.contains("--data-dir <DATA_DIR>"));
    assert!(server_help.starts_with("Usage:"));
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
fn ssh_config_uses_stable_alias_and_shell_safe_proxy_arguments() {
    let target_id = Uuid::new_v4();
    let target = TargetView {
        target_id,
        name: "-unsafe\nProxyCommand evil".to_owned(),
        enabled: false,
        online: true,
    };
    let config = Config {
        server_url: "https://example.test".to_owned(),
        data_dir: "/tmp/kmesh %home".into(),
        profile: "%h-profile".to_owned(),
        ..Config::default()
    };
    let config_path = std::path::Path::new("/tmp/config with %tokens.toml");

    let rendered = ssh_config::render(&target, &config, Some(config_path));
    assert!(rendered.starts_with(&format!("Host {target_id}\n")));
    assert_eq!(rendered.matches("\nHost ").count(), 0);
    assert!(rendered.contains("--config '/tmp/config with %%tokens.toml'"));
    assert!(rendered.contains("--data-dir '/tmp/kmesh %%home'"));
    assert!(rendered.contains("--profile '%%h-profile'"));
    assert!(rendered.contains(&format!("HostKeyAlias kmesh/{target_id}")));
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
