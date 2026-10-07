use anyhow::{Context, Result, anyhow};
use uuid::Uuid;

use crate::client::cli::Cli;
use crate::config::resolve_path;
use crate::protocol::TargetView;

pub fn find_target(targets: &[TargetView], selector: &str) -> Result<TargetView> {
    if let Ok(target_id) = Uuid::parse_str(selector) {
        return targets
            .iter()
            .find(|target| target.target_id == target_id)
            .cloned()
            .ok_or_else(|| anyhow!("target {target_id} is not available to this account"));
    }
    let matches = targets
        .iter()
        .filter(|target| target.name == selector)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [target] => Ok((*target).clone()),
        [] => Err(anyhow!(
            "target {selector} is not available to this account"
        )),
        _ => Err(anyhow!("target name {selector} is ambiguous; use its UUID")),
    }
}

pub fn render(target: &TargetView, cli: &Cli) -> Result<String> {
    let host_alias = if safe_host_alias(&target.name) {
        target.name.as_str()
    } else {
        return render_with_alias(target, &target.target_id.to_string(), cli);
    };
    render_with_alias(target, host_alias, cli)
}

fn render_with_alias(target: &TargetView, host_alias: &str, cli: &Cli) -> Result<String> {
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
    args.extend(["proxy".to_owned(), target.target_id.to_string()]);
    let command = args.join(" ");
    Ok(format!(
        "Host {host_alias}\n    ProxyCommand {command}\n    HostKeyAlias kmesh/{}\n    ControlMaster auto\n    ControlPath ~/.ssh/kmesh-%C\n    ControlPersist 5m\n\n",
        target.target_id
    ))
}

fn ssh_shell_arg(value: &str) -> String {
    let escaped = value.replace('%', "%%");
    format!("'{}'", escaped.replace('\'', "'\\''"))
}

fn safe_host_alias(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
