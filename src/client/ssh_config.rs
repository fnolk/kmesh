use crate::client::cli::Cli;
use crate::config::resolve_path;
use crate::protocol::TargetView;
use anyhow::{Context, Result, anyhow};

use super::profile::component_hash;

pub fn find_target(targets: &[TargetView], selector: &str) -> Result<TargetView> {
    let target_id = selector.trim().to_ascii_lowercase();
    targets
        .iter()
        .find(|target| target.target_id == target_id)
        .cloned()
        .ok_or_else(|| anyhow!("target ID {target_id} is not available to this account"))
}

pub fn render(target: &TargetView, cli: &Cli, server_origin: &str) -> Result<String> {
    let current_dir =
        std::env::current_dir().context("resolve current directory for SSH ProxyCommand")?;
    let mut args = vec!["kmesh".to_owned()];
    if let Some(config_path) = &cli.config {
        let config_path = resolve_path(config_path, &current_dir);
        args.extend([
            "--config".to_owned(),
            ssh_shell_arg(&config_path.to_string_lossy()),
        ]);
    }
    if let Some(data_dir) = &cli.data_dir {
        let data_dir = resolve_path(data_dir, &current_dir);
        args.extend([
            "--data-dir".to_owned(),
            ssh_shell_arg(&data_dir.to_string_lossy()),
        ]);
    }
    if let Some(profile) = &cli.profile {
        args.extend(["--profile".to_owned(), ssh_shell_arg(profile)]);
    }
    if let Some(server_addr) = &cli.server_addr {
        args.extend(["--server-addr".to_owned(), ssh_shell_arg(server_addr)]);
    }
    if let Some(server_port) = cli.server_port {
        args.extend(["--server-port".to_owned(), server_port.to_string()]);
    }
    args.extend(["proxy".to_owned(), target.target_id.clone()]);
    let command = args.join(" ");
    let server_namespace = component_hash(server_origin);
    Ok(format!(
        "Host {}\n    ProxyCommand {command}\n    HostKeyAlias kmesh/{server_namespace}/{}\n    ControlMaster auto\n    ControlPath ~/.ssh/kmesh-%C\n    ControlPersist 5m\n\n",
        target.name, target.target_id,
    ))
}

fn ssh_shell_arg(value: &str) -> String {
    let escaped = value.replace('%', "%%");
    format!("'{}'", escaped.replace('\'', "'\\''"))
}
