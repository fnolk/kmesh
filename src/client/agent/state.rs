use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::{
    client::profile::{ensure_private_dir, write_json_atomic},
    config::server_origin,
    protocol::AgentCredentials,
    target_id::is_target_slug,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct AgentState {
    pub(super) target_id: String,
    pub(super) server_addr: String,
    pub(super) server_port: u16,
    pub(super) agent_token: String,
    pub(super) ticket_public_key_pem: String,
    pub(super) endpoint_secret_key: String,
    pub(super) ssh_address: SocketAddr,
    pub(super) ssh_connect_timeout_secs: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct PendingAgentIdentity {
    pub(super) server_addr: String,
    pub(super) server_port: u16,
    pub(super) endpoint_secret_key: String,
}

impl AgentState {
    pub(super) fn credentials(&self) -> AgentCredentials {
        AgentCredentials {
            target_id: self.target_id.clone(),
            agent_token: self.agent_token.clone(),
            ticket_public_key_pem: self.ticket_public_key_pem.clone(),
            endpoint_secret_key: self.endpoint_secret_key.clone(),
        }
    }

    pub(super) fn server_origin(&self) -> Result<String> {
        server_origin(&self.server_addr, self.server_port)
    }
}

pub(super) fn normalize_target_id(target_id: &str) -> Result<String> {
    let target_id = target_id.trim().to_ascii_lowercase();
    anyhow::ensure!(
        is_target_slug(&target_id),
        "Use 1 to 64 ASCII characters for the target ID. Use letters, numbers, periods, underscores, or hyphens. Start with a letter or number."
    );
    Ok(target_id)
}

pub fn data_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    let path = if let Some(path) = explicit {
        crate::config::resolve_path(
            path,
            &std::env::current_dir().context("The current directory must be available.")?,
        )
    } else {
        default_data_dir()?
    };
    std::path::absolute(path).context("Get the full path for the agent data directory.")
}

pub fn prepare_data_dir(data_dir: &Path) -> Result<PathBuf> {
    ensure_private_dir(data_dir)?;
    let data_dir =
        fs::canonicalize(data_dir).context("Check access to the agent data directory.")?;
    data_dir
        .to_str()
        .context("Use UTF-8 characters in the data path.")?;
    Ok(data_dir)
}

fn default_data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let is_root = nix::unistd::geteuid().is_root();
        let state_dir = if is_root { None } else { dirs::state_dir() };
        linux_data_dir(is_root, state_dir)
    }

    #[cfg(not(target_os = "linux"))]
    dirs::data_local_dir()
        .map(|path| path.join("kmesh"))
        .ok_or_else(|| anyhow!("Set --data-dir to a directory that stores the agent state."))
}

#[cfg(target_os = "linux")]
fn linux_data_dir(is_root: bool, state_dir: Option<PathBuf>) -> Result<PathBuf> {
    if is_root {
        Ok(PathBuf::from("/var/lib/kmesh"))
    } else {
        state_dir
            .map(|path| path.join("kmesh"))
            .ok_or_else(|| anyhow!("Set --data-dir to a directory that stores the agent state."))
    }
}

pub(super) fn state_path(data_dir: &Path, target_id: &str) -> PathBuf {
    data_dir.join("agents").join(target_id).join("agent.json")
}

pub(super) fn pending_path(data_dir: &Path, target_id: &str) -> PathBuf {
    let mut path = state_path(data_dir, target_id);
    path.set_file_name("agent.pending.json");
    path
}

pub(super) fn ensure_target_dir(data_dir: &Path, target_id: &str) -> Result<()> {
    let state_path = state_path(data_dir, target_id);
    let target_dir = state_path.parent().expect("agent state path has a parent");
    ensure_private_dir(data_dir)?;
    ensure_private_dir(target_dir.parent().expect("agent target path has a parent"))?;
    ensure_private_dir(target_dir)
}

pub(super) fn load(data_dir: &Path, target_id: &str) -> Result<AgentState> {
    load_optional(data_dir, target_id)?
        .ok_or_else(|| anyhow!("Run `agent enroll` to create state for this target."))
}

pub(super) fn load_optional(data_dir: &Path, target_id: &str) -> Result<Option<AgentState>> {
    let path = state_path(data_dir, target_id);
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .context("Read agent state.")
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("Read agent state."),
    }
}

pub(super) fn save(data_dir: &Path, state: &AgentState) -> Result<()> {
    ensure_target_dir(data_dir, &state.target_id)?;
    write_json_atomic(&state_path(data_dir, &state.target_id), state)
}

pub(super) fn save_pending(
    data_dir: &Path,
    target_id: &str,
    identity: &PendingAgentIdentity,
) -> Result<()> {
    ensure_target_dir(data_dir, target_id)?;
    write_json_atomic(&pending_path(data_dir, target_id), identity)
}

pub(super) fn load_pending(
    data_dir: &Path,
    target_id: &str,
) -> Result<Option<PendingAgentIdentity>> {
    let path = pending_path(data_dir, target_id);
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .context("Read pending agent identity.")
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("Read pending agent identity."),
    }
}

pub(super) fn clear_pending(data_dir: &Path, target_id: &str) -> Result<()> {
    let path = pending_path(data_dir, target_id);
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Remove pending agent identity."),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use uuid::Uuid;

    fn test_state(target_id: &str) -> AgentState {
        AgentState {
            target_id: target_id.to_owned(),
            server_addr: "localhost".to_owned(),
            server_port: 9443,
            agent_token: "agent-token".to_owned(),
            ticket_public_key_pem: "ticket-key".to_owned(),
            endpoint_secret_key: "device-key".to_owned(),
            ssh_address: "127.0.0.1:22".parse().unwrap(),
            ssh_connect_timeout_secs: 10,
        }
    }

    #[test]
    fn target_ids_follow_the_server_slug_rule_before_path_use() {
        assert_eq!(
            normalize_target_id("Build_Machine.1").unwrap(),
            "build_machine.1"
        );
        for target_id in ["../outside", "/tmp", "a/b", "-build", ".", "a\\b"] {
            assert!(normalize_target_id(target_id).is_err(), "{target_id}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_data_directory_selects_root_and_user_locations() {
        assert_eq!(
            linux_data_dir(true, None).unwrap(),
            PathBuf::from("/var/lib/kmesh")
        );
        let state_dir = PathBuf::from("/home/alice/.local/state");
        assert_eq!(
            linux_data_dir(false, Some(state_dir.clone())).unwrap(),
            state_dir.join("kmesh")
        );
        assert!(linux_data_dir(false, None).is_err());
    }

    #[test]
    fn explicit_data_directory_is_absolute_and_private() {
        let root = std::env::temp_dir().join(format!("kmesh agent {}", Uuid::new_v4()));
        let path = data_dir(Some(&root)).unwrap();
        assert!(path.is_absolute());
        let prepared = prepare_data_dir(&path).unwrap();
        assert!(prepared.to_string_lossy().contains("kmesh agent"));
        assert_eq!(fs::canonicalize(&path).unwrap(), prepared);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&prepared).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn state_uses_the_target_directory_and_private_modes() {
        let root = std::env::temp_dir().join(format!("kmesh-agent-state-{}", Uuid::new_v4()));
        save(&root, &test_state("build-machine")).unwrap();
        let path = state_path(&root, "build-machine");
        let state = load(&root, "build-machine").unwrap();
        assert_eq!(state.server_port, 9443);
        assert_eq!(state.ssh_address, "127.0.0.1:22".parse().unwrap());
        assert_eq!(state.ssh_connect_timeout_secs, 10);
        assert!(!state_path(&root, "other-machine").exists());
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_identity_records_its_server_and_uses_the_shared_target_directory() {
        let root = std::env::temp_dir().join(format!("kmesh-agent-pending-{}", Uuid::new_v4()));
        let identity = PendingAgentIdentity {
            server_addr: "localhost".to_owned(),
            server_port: 9443,
            endpoint_secret_key: "device-key".to_owned(),
        };
        save_pending(&root, "build-machine", &identity).unwrap();
        assert_eq!(
            load_pending(&root, "build-machine")
                .unwrap()
                .unwrap()
                .server_port,
            9443
        );
        assert_eq!(
            pending_path(&root, "build-machine").file_name().unwrap(),
            "agent.pending.json"
        );
        clear_pending(&root, "build-machine").unwrap();
        assert!(load_pending(&root, "build-machine").unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
