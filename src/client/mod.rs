mod admin;
mod agent;
mod api;
mod auth;
mod cli;
mod profile;
mod proxy;
pub mod ssh_config;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};

use crate::{config::Config, server};

pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + ?Sized> AsyncReadWrite for T {}

pub use api::canonical_origin;
pub use cli::{Cli, Command};

#[derive(Clone)]
pub struct ClientContext {
    pub config: Config,
    pub config_path: Option<PathBuf>,
    pub api: api::Api,
    pub profiles: profile::ProfileStore,
}

impl ClientContext {
    async fn new(cli: &Cli) -> Result<Self> {
        let (config, config_path) = load_config(cli)?;
        let api = api::Api::new(&config).await?;
        let profiles =
            profile::ProfileStore::new(&config.data_dir, &config.server_url, &config.profile);
        Ok(Self {
            config,
            config_path,
            api,
            profiles,
        })
    }
}

fn load_config(cli: &Cli) -> Result<(Config, Option<PathBuf>)> {
    let defaults = Config::default();
    let config_path = cli.config.clone().unwrap_or_else(|| {
        cli.data_dir
            .clone()
            .unwrap_or_else(|| defaults.data_dir.clone())
            .join("config.toml")
    });
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
    if let Some(data_dir) = &cli.data_dir {
        config.data_dir = data_dir.clone();
    }
    if let Some(profile) = &cli.profile {
        config.profile = profile.trim().to_lowercase();
    } else {
        config.profile = config.profile.trim().to_lowercase();
    }
    if let Some(server_url) = &cli.server_url {
        config.server_url = server_url.clone();
    }
    config.server_url = api::canonical_origin(&config.server_url)?;
    let selected_config = (explicit_config || config_path.is_file()).then_some(config_path);
    Ok((config, selected_config))
}

pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        cli::Command::Server { command } => match command {
            cli::ServerCommand::Init(args) => {
                let data_dir = cli
                    .data_dir
                    .as_deref()
                    .context("server init requires --data-dir")?;
                let password = auth::read_password("请设置管理员密码：", args.password_stdin)?;
                let issuer = api::canonical_origin(&args.issuer)?;
                server::initialize(data_dir, &args.admin, &password, &issuer).await?;
                println!("服务端已初始化。issuer={issuer}");
            }
            cli::ServerCommand::Run(args) => {
                let data_dir = cli
                    .data_dir
                    .clone()
                    .context("server run requires --data-dir")?;
                let issuer = api::canonical_origin(&args.issuer)?;
                server::run(server::ServerOptions {
                    data_dir,
                    issuer,
                    bind: args.bind,
                    tls_cert: args.tls_cert.clone(),
                    tls_key: args.tls_key.clone(),
                    qad_bind: args.qad_bind,
                    disable_private_relay: args.disable_private_relay,
                })
                .await?;
            }
        },
        cli::Command::Agent { command } => {
            let context = ClientContext::new(&cli).await?;
            match command {
                cli::AgentCommand::Enroll(args) => {
                    agent::enroll(&context, args.target_id, &args.enrollment_code).await?;
                    println!("目标 {} 已注册。", args.target_id);
                }
                cli::AgentCommand::Run(args) => {
                    agent::run(&context, args.target_id).await?;
                }
            }
        }
        cli::Command::Login(args) => {
            let context = ClientContext::new(&cli).await?;
            auth::login(&context, args).await?;
            println!(
                "登录成功。server={} profile={}",
                context.config.server_url, context.config.profile
            );
        }
        cli::Command::Logout => {
            let context = ClientContext::new(&cli).await?;
            auth::logout(&context).await?;
            println!("已退出当前登录。");
        }
        cli::Command::Targets { command } => {
            let context = ClientContext::new(&cli).await?;
            match command {
                cli::TargetsCommand::List => {
                    let token = auth::valid_access_token(&context).await?;
                    let targets = context.api.targets(&token).await?;
                    println!("目标列表：");
                    for target in targets {
                        println!(
                            "{}\t{}\t{}\t{}",
                            target.target_id,
                            target.name,
                            if target.enabled {
                                "enabled"
                            } else {
                                "disabled"
                            },
                            if target.online { "online" } else { "offline" }
                        );
                    }
                }
            }
        }
        cli::Command::SshConfig { target } => {
            let context = ClientContext::new(&cli).await?;
            let token = auth::valid_access_token(&context).await?;
            let targets = context.api.targets(&token).await?;
            let target = ssh_config::find_target(&targets, target)?;
            print!(
                "{}",
                ssh_config::render(&target, &context.config, context.config_path.as_deref())
            );
        }
        cli::Command::Proxy { target_id } => {
            let context = ClientContext::new(&cli).await?;
            proxy::run(&context, *target_id).await?;
        }
        cli::Command::Admin(args) => {
            let context = ClientContext::new(&cli).await?;
            admin::run(&context, args).await?;
        }
    }
    Ok(())
}
