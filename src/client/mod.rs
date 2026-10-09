mod admin;
mod admin_view;
mod agent;
mod api;
mod auth;
mod cli;
mod diagnostics;
mod groups;
mod output;
mod profile;
mod proxy;
mod route;
pub mod ssh_config;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::{
    config::{Config, resolve_path},
    server,
};

pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + ?Sized> AsyncReadWrite for T {}

pub use crate::config::canonical_origin;
pub use cli::{Cli, Command};

/// Format an error chain as one safe terminal line.
pub fn format_error(error: &anyhow::Error) -> String {
    output::cell(&format!("{error:#}"))
}

#[derive(Clone)]
pub struct ClientContext {
    pub config: Config,
    pub api: api::Api,
    pub profiles: profile::ProfileStore,
}

impl ClientContext {
    async fn new(config: &Config) -> Result<Self> {
        let api = api::Api::new(config).await?;
        let profiles =
            profile::ProfileStore::new(&config.data_dir, &config.server_origin()?, &config.profile);
        Ok(Self {
            config: config.clone(),
            api,
            profiles,
        })
    }
}

fn load_config(cli: &Cli) -> Result<Config> {
    load_config_at(cli, &Config::default_config_path())
}

fn load_config_at(cli: &Cli, default_config_path: &Path) -> Result<Config> {
    let defaults = Config::default();
    let current_dir = std::env::current_dir().context("resolve current directory")?;
    let config_path = cli
        .config
        .as_deref()
        .map(|path| resolve_path(path, &current_dir))
        .unwrap_or_else(|| default_config_path.to_path_buf());
    let explicit_config = cli.config.is_some();
    let mut config = if explicit_config {
        anyhow::ensure!(
            config_path.is_file(),
            "configuration file does not exist: {}",
            config_path.display()
        );
        toml::from_str(&fs::read_to_string(&config_path).context("read configuration")?)
            .with_context(|| format!("parse configuration at {}", config_path.display()))?
    } else if config_path.exists() {
        toml::from_str(&fs::read_to_string(&config_path).context("read configuration")?)
            .with_context(|| format!("parse configuration at {}", config_path.display()))?
    } else {
        defaults
    };
    let config_dir = config_path
        .parent()
        .context("configuration file path has no parent directory")?;
    config.data_dir = resolve_path(&config.data_dir, config_dir);
    config.auth.key = config
        .auth
        .key
        .as_deref()
        .map(|path| resolve_path(path, config_dir));
    if let Some(data_dir) = &cli.data_dir {
        config.data_dir = resolve_path(data_dir, &current_dir);
    }
    if let Some(profile) = &cli.profile {
        config.profile = profile.trim().to_lowercase();
    } else {
        config.profile = config.profile.trim().to_lowercase();
    }
    if let Some(server_addr) = &cli.server_addr {
        config.server_addr = server_addr.clone();
    }
    if let Some(server_port) = cli.server_port {
        config.server_port = server_port;
    }
    config.server_origin()?;
    Ok(config)
}

pub async fn run(cli: Cli) -> Result<()> {
    if let cli::Command::Agent { command } = &cli.command {
        return run_agent(&cli, command).await;
    }

    let config = load_config(&cli)?;
    match &cli.command {
        cli::Command::Status { json } => {
            let context = ClientContext::new(&config).await?;
            diagnostics::status(&context, *json).await?;
        }
        cli::Command::Doctor { target, json } => {
            let context = ClientContext::new(&config).await?;
            diagnostics::doctor(&context, target, *json).await?;
        }
        cli::Command::Access {
            command: cli::AccessCommand::Explain { user, target, json },
        } => {
            let context = ClientContext::new(&config).await?;
            diagnostics::explain(&context, user, target, *json).await?;
        }
        cli::Command::Server { command } => match command {
            cli::ServerCommand::Init(args) => {
                let issuer = config.server_origin()?;
                let initial_token =
                    server::initialize(&config.data_dir, &args.admin, &issuer).await?;
                println!("Server initialized. issuer={issuer}");
                if let Some(token) = initial_token {
                    println!("Initial administrator API token (shown once): {token}");
                }
            }
            cli::ServerCommand::Run(args) => {
                let issuer = config.server_origin()?;
                let bind_addr = args.bind_addr.unwrap_or(config.server.bind_addr);
                let udp_port = args.udp_port.unwrap_or(config.server.udp_port);
                anyhow::ensure!(udp_port != 0, "UDP port must be between 1 and 65535");
                let disable_private_relay = args
                    .disable_private_relay
                    .unwrap_or(config.server.disable_private_relay);
                server::run(server::ServerOptions {
                    data_dir: config.data_dir.clone(),
                    issuer,
                    bind: std::net::SocketAddr::new(bind_addr, config.server_port),
                    qad_bind: std::net::SocketAddr::new(bind_addr, udp_port),
                    disable_private_relay,
                })
                .await?;
            }
        },
        cli::Command::Agent { .. } => unreachable!("agent commands run before config loading"),
        cli::Command::Login(args) => {
            let context = ClientContext::new(&config).await?;
            auth::login(&context, args).await?;
            println!(
                "Login complete. server={} profile={}",
                context.api.issuer(),
                output::cell(&context.config.profile)
            );
        }
        cli::Command::Logout => {
            let context = ClientContext::new(&config).await?;
            auth::logout(&context).await?;
            println!("Logout complete.");
        }
        cli::Command::Targets { command } => {
            let context = ClientContext::new(&config).await?;
            match command {
                cli::TargetsCommand::List => {
                    let token = auth::valid_access_token(&context).await?;
                    let targets = context.api.targets(&token).await?;
                    let rows = targets
                        .into_iter()
                        .map(|target| {
                            vec![
                                target.target_id,
                                target.name,
                                if target.enabled {
                                    "enabled"
                                } else {
                                    "disabled"
                                }
                                .to_owned(),
                                if target.online { "online" } else { "offline" }.to_owned(),
                            ]
                        })
                        .collect();
                    output::print_table(
                        "Targets",
                        &["TARGET", "NAME", "STATE", "CONNECTION"],
                        rows,
                    );
                }
            }
        }
        cli::Command::SshConfig { target } => {
            let context = ClientContext::new(&config).await?;
            let token = auth::valid_access_token(&context).await?;
            let targets = context.api.targets(&token).await?;
            let target = ssh_config::find_target(&targets, target)?;
            print!(
                "{}",
                ssh_config::render(&target, &cli, context.api.issuer())?
            );
        }
        cli::Command::Proxy { target_id } => {
            let context = ClientContext::new(&config).await?;
            proxy::run(&context, target_id.trim().to_ascii_lowercase()).await?;
        }
        cli::Command::Admin(args) => {
            let context = ClientContext::new(&config).await?;
            admin::run(&context, args).await?;
        }
    }
    Ok(())
}

async fn run_agent(cli: &Cli, command: &cli::AgentCommand) -> Result<()> {
    anyhow::ensure!(
        cli.config.is_none(),
        "Remove --config from the agent command."
    );
    anyhow::ensure!(
        cli.profile.is_none(),
        "Remove --profile from the agent command."
    );
    let data_dir = agent::data_dir(cli.data_dir.as_deref())?;
    match command {
        cli::AgentCommand::Enroll(args) => {
            let data_dir = agent::prepare_data_dir(&data_dir)?;
            let server_addr = cli.server_addr.as_deref().unwrap_or("localhost");
            let server_port = cli.server_port.unwrap_or(9443);
            let target_id = agent::enroll(
                server_addr,
                server_port,
                &data_dir,
                args.target_id.clone(),
                &args.enrollment_code,
                args.ssh_address,
                args.ssh_connect_timeout_secs,
            )
            .await?;
            let data_dir = data_dir.to_str().expect("prepared data path is UTF-8");
            let target_id = shlex::try_quote(&target_id)?;
            println!("Target ID: {}", output::cell(&target_id));
            println!("Data directory: {}", output::cell(data_dir));
            println!("Start the agent:");
            println!(
                "  kmesh --data-dir {} agent run --target-id {}",
                shlex::try_quote(data_dir)?,
                target_id
            );
        }
        cli::AgentCommand::Run(args) => {
            anyhow::ensure!(
                cli.server_addr.is_none() && cli.server_port.is_none(),
                "Use the saved server settings with `agent run`."
            );
            agent::run(&data_dir, args.target_id.clone()).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use clap::error::ErrorKind;
    use clap::{CommandFactory, Parser};
    use uuid::Uuid;

    use super::{Cli, load_config_at};

    #[test]
    fn long_version_displays_shadow_build_metadata() {
        let error = Cli::try_parse_from(["kmesh", "--version"])
            .expect_err("--version exits after displaying build metadata");
        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        let output = error.to_string();
        assert!(output.contains(crate::build::PKG_VERSION));
        assert!(output.contains(crate::build::SHORT_COMMIT));
        assert!(output.contains(&format!("source_ref:{}", crate::version::SOURCE_REF)));
        assert_eq!(
            Cli::command().get_long_version(),
            Some(crate::version::CLI_LONG_VERSION)
        );
    }

    #[test]
    fn default_config_loads_from_its_path_and_cli_overrides_toml() {
        let directory = std::env::temp_dir().join(format!("kmesh-config-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temporary config directory");
        let config_path = directory.join("config.toml");
        fs::write(
            &config_path,
            "server_addr = \"toml.example\"\nserver_port = 9443\nprofile = \"work\"\ndata_dir = \"state\"\n\n[auth]\nmethod = \"public-key\"\nusername = \"toml-user\"\nkey = \"keys/id_ed25519\"\ntoken = \"toml-token\"\n\n[server]\nudp_port = 4000\n",
        )
        .expect("write temporary config");
        let target = Uuid::new_v4().to_string();
        let cli = Cli::try_parse_from([
            "kmesh",
            "--data-dir",
            "cli-state",
            "--profile",
            "OPS",
            "--server-addr",
            "cli.example",
            "--server-port",
            "9555",
            "proxy",
            &target,
        ])
        .expect("parse CLI overrides");

        let config = load_config_at(&cli, &config_path).expect("load default config path");
        assert_eq!(config.server_addr, "cli.example");
        assert_eq!(config.server_port, 9555);
        assert_eq!(config.profile, "ops");
        assert_eq!(
            config.auth.method,
            Some(crate::config::LoginMethod::PublicKey)
        );
        assert_eq!(config.auth.username.as_deref(), Some("toml-user"));
        assert_eq!(config.auth.key, Some(directory.join("keys/id_ed25519")));
        assert_eq!(config.auth.token.as_deref(), Some("toml-token"));
        assert_eq!(config.server.udp_port, 4000);
        assert_eq!(
            config.data_dir,
            std::env::current_dir().unwrap().join("cli-state")
        );
        assert_eq!(config.server_origin().unwrap(), "https://cli.example:9555");
        fs::remove_dir_all(directory).expect("remove temporary config directory");
    }

    #[test]
    fn explicit_config_path_is_required_to_exist() {
        let directory = std::env::temp_dir().join(format!("kmesh-config-{}", Uuid::new_v4()));
        let cli = Cli::try_parse_from(["kmesh", "--config", directory.to_str().unwrap(), "logout"])
            .expect("parse explicit config argument");
        assert!(load_config_at(&cli, &PathBuf::from("unused-config.toml")).is_err());
    }

    #[test]
    fn non_login_commands_load_config_without_complete_auth_settings() {
        let directory = std::env::temp_dir().join(format!("kmesh-config-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temporary config directory");
        let config_path = directory.join("config.toml");
        fs::write(&config_path, "server_addr = \"example.test\"\n")
            .expect("write config without login settings");
        let cli =
            Cli::try_parse_from(["kmesh", "--config", config_path.to_str().unwrap(), "logout"])
                .expect("parse non-login command");

        let config = load_config_at(&cli, &config_path).expect("load non-login config");
        assert!(config.auth.method.is_none());
        assert!(config.auth.token.is_none());
        fs::remove_dir_all(directory).expect("remove temporary config directory");
    }

    #[tokio::test]
    async fn udp_port_is_a_server_setting_and_server_run_rejects_zero() {
        let directory = std::env::temp_dir().join(format!("kmesh-config-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temporary config directory");
        let config_path = directory.join("config.toml");
        fs::write(&config_path, "data_dir = \".\"\n\n[server]\nudp_port = 0\n")
            .expect("write config");

        let client_cli =
            Cli::try_parse_from(["kmesh", "--config", config_path.to_str().unwrap(), "logout"])
                .expect("parse client command");
        assert_eq!(
            load_config_at(&client_cli, &config_path)
                .unwrap()
                .server
                .udp_port,
            0
        );

        let server_cli = Cli::try_parse_from([
            "kmesh",
            "--config",
            config_path.to_str().unwrap(),
            "server",
            "run",
        ])
        .expect("parse server command");
        let error = super::run(server_cli)
            .await
            .expect_err("server run rejects UDP port zero");
        assert!(format!("{error:#}").contains("UDP port must be between 1 and 65535"));

        let overridden_cli = Cli::try_parse_from([
            "kmesh",
            "--config",
            config_path.to_str().unwrap(),
            "server",
            "run",
            "--udp-port",
            "4000",
        ])
        .expect("parse server port override");
        let error = super::run(overridden_cli)
            .await
            .expect_err("server must be initialized before it can run");
        assert!(
            format!("{error:#}").contains("server is not initialized"),
            "unexpected server startup error: {error:#}"
        );
        fs::remove_dir_all(directory).expect("remove temporary config directory");
    }
}
