use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::protocol::{AgentCredentials, LoginTokens};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedLogin {
    pub server_url: String,
    pub profile: String,
    pub username: String,
    pub tokens: LoginTokens,
}

#[derive(Clone, Debug)]
pub struct ProfileStore {
    data_dir: PathBuf,
    profile_dir: PathBuf,
}

impl ProfileStore {
    pub fn new(data_dir: &Path, server_url: &str, profile: &str) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            profile_dir: data_dir
                .join("profiles")
                .join(component_hash(server_url))
                .join(component_hash(&normalize_profile(profile))),
        }
    }

    pub fn login_path(&self, username: &str) -> PathBuf {
        self.profile_dir.join(format!(
            "{}.json",
            component_hash(&normalize_username(username))
        ))
    }

    pub fn active_user_path(&self) -> PathBuf {
        self.profile_dir.join("active-user")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.profile_dir.join("refresh.lock")
    }

    pub fn load(&self, username: &str) -> Result<Option<SavedLogin>> {
        read_json(&self.login_path(username))
    }

    pub fn save(&self, saved: &SavedLogin) -> Result<()> {
        self.ensure_profile_dir()?;
        write_json_atomic(&self.login_path(&saved.username), saved)
    }

    pub fn delete(&self, username: &str) -> Result<()> {
        match fs::remove_file(self.login_path(username)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove saved login"),
        }
    }

    pub fn set_active_user(&self, username: &str) -> Result<()> {
        self.ensure_profile_dir()?;
        write_bytes_atomic(
            &self.active_user_path(),
            normalize_username(username).as_bytes(),
        )
    }

    pub fn active_user(&self) -> Result<String> {
        let mut username = String::new();
        File::open(self.active_user_path())
            .context("read active kmesh login")?
            .read_to_string(&mut username)
            .context("read active username")?;
        Ok(normalize_username(&username))
    }

    pub fn lock_refresh(&self) -> Result<File> {
        self.ensure_profile_dir()?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(self.lock_path())
            .context("open refresh lock")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            lock.set_permissions(fs::Permissions::from_mode(0o600))
                .context("set refresh lock permissions")?;
        }
        lock.lock_exclusive().context("lock saved login")?;
        Ok(lock)
    }

    pub fn clear_active_user_if(&self, username: &str) -> Result<()> {
        let active = match fs::read_to_string(self.active_user_path()) {
            Ok(active) => normalize_username(&active),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("read active kmesh login"),
        };
        if active != normalize_username(username) {
            return Ok(());
        }
        match fs::remove_file(self.active_user_path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove active kmesh login"),
        }
    }

    fn ensure_profile_dir(&self) -> Result<()> {
        ensure_private_dir(&self.data_dir)?;
        ensure_private_dir(&self.data_dir.join("profiles"))?;
        ensure_private_dir(
            self.profile_dir
                .parent()
                .expect("profile path has a server scope"),
        )?;
        ensure_private_dir(&self.profile_dir)
    }
}

pub fn agent_credentials_path(data_dir: &Path, target_id: Uuid) -> PathBuf {
    data_dir.join("agents").join(format!("{target_id}.json"))
}

pub fn load_agent_credentials(data_dir: &Path, target_id: Uuid) -> Result<AgentCredentials> {
    read_json(&agent_credentials_path(data_dir, target_id))?
        .context("target agent has not been enrolled")
}

pub fn save_agent_credentials(data_dir: &Path, credentials: &AgentCredentials) -> Result<()> {
    ensure_private_dir(data_dir)?;
    write_json_atomic(
        &agent_credentials_path(data_dir, credentials.target_id),
        credentials,
    )
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("serialize secure state")?;
    write_bytes_atomic(path, &bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .context("decode saved kmesh state")
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("read saved kmesh state"),
    }
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("secure state path has no parent")?;
    ensure_private_dir(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("create secure temporary file")?;
    file.write_all(bytes)
        .context("write secure temporary file")?;
    file.sync_all().context("sync secure temporary file")?;
    fs::rename(&temporary, path).context("replace secure state file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("set secure state file permissions")?;
    }
    Ok(())
}

fn component_hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

pub fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}

fn normalize_profile(profile: &str) -> String {
    profile.trim().to_lowercase()
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("create private directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set private directory permissions {}", path.display()))?;
    }
    Ok(())
}
