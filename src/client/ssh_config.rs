use anyhow::{Result, anyhow};
use std::path::Path;
use uuid::Uuid;

use crate::config::Config;
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

pub fn render(target: &TargetView, config: &Config, config_path: Option<&Path>) -> String {
    let host_alias = if safe_host_alias(&target.name) {
        target.name.as_str()
    } else {
        return render_with_alias(target, &target.target_id.to_string(), config, config_path);
    };
    render_with_alias(target, host_alias, config, config_path)
}

fn render_with_alias(
    target: &TargetView,
    host_alias: &str,
    config: &Config,
    config_path: Option<&Path>,
) -> String {
    let mut args = vec!["kmesh".to_owned()];
    if let Some(config_path) = config_path {
        args.extend([
            "--config".to_owned(),
            ssh_shell_arg(&config_path.to_string_lossy()),
        ]);
    }
    args.extend([
        "--server-url".to_owned(),
        ssh_shell_arg(&config.server_url),
        "--data-dir".to_owned(),
        ssh_shell_arg(&config.data_dir.to_string_lossy()),
        "--profile".to_owned(),
        ssh_shell_arg(&config.profile),
        "proxy".to_owned(),
        target.target_id.to_string(),
    ]);
    let command = args.join(" ");
    format!(
        "Host {host_alias}\n    ProxyCommand {command}\n    HostKeyAlias kmesh/{}\n    ControlMaster auto\n    ControlPath ~/.ssh/kmesh-%C\n    ControlPersist 5m\n\n",
        target.target_id
    )
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
