use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{
    config::AuthMethod,
    protocol::{LoginTokens, PublicKeyChallengeRequest, PublicKeyLoginRequest, RefreshRequest},
};

use super::{
    ClientContext,
    profile::{SavedSession, normalize_username},
};

pub async fn valid_access_token(context: &ClientContext) -> Result<String> {
    match context
        .config
        .auth
        .method
        .context("Set [auth].method to token or public-key in the configuration.")?
    {
        AuthMethod::Token => configured_api_token(context),
        AuthMethod::PublicKey => public_key_access_token(context).await,
    }
}

fn configured_api_token(context: &ClientContext) -> Result<String> {
    let environment_token = std::env::var_os("KMESH_TOKEN")
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow!("KMESH_TOKEN must contain valid UTF-8"))
        })
        .transpose()?;
    let token = environment_token
        .as_deref()
        .or(context.config.auth.token.as_deref())
        .context("Set KMESH_TOKEN or [auth].token in the configuration.")?;
    anyhow::ensure!(!token.trim().is_empty(), "API token is empty");
    Ok(token.to_owned())
}

async fn public_key_access_token(context: &ClientContext) -> Result<String> {
    let username = context
        .config
        .auth
        .username
        .as_deref()
        .context("Set [auth].username in the configuration.")?;
    let username = normalize_username(username);
    anyhow::ensure!(!username.is_empty(), "username is empty");
    let key_path = context
        .config
        .auth
        .key
        .as_deref()
        .context("Set [auth].key in the configuration.")?;
    let public_key = public_key(key_path)?;
    let fingerprint = public_key_fingerprint(&public_key)?;

    let profiles = context.profiles.clone();
    let _lock = tokio::task::spawn_blocking(move || profiles.lock_refresh())
        .await
        .context("session lock task failed")??;
    let now = unix_now()?;
    if let Some(saved) = context.profiles.load(&username)? {
        if saved.public_key_fingerprint == fingerprint {
            if saved.tokens.access_expires_at > now.saturating_add(30) {
                return Ok(saved.tokens.access_token);
            }
            if saved.tokens.refresh_expires_at > now {
                return refresh_public_key_session(context, &username, fingerprint, saved).await;
            }
        }
        context.profiles.delete(&username)?;
    }

    let tokens = public_key_login(context, &username, key_path, &public_key).await?;
    let access_token = tokens.access_token.clone();
    context.profiles.save(
        &username,
        &SavedSession {
            public_key_fingerprint: fingerprint,
            tokens,
        },
    )?;
    Ok(access_token)
}

async fn refresh_public_key_session(
    context: &ClientContext,
    username: &str,
    fingerprint: String,
    saved: SavedSession,
) -> Result<String> {
    match context
        .api
        .refresh(&RefreshRequest {
            refresh_token: saved.tokens.refresh_token,
        })
        .await
    {
        Ok(tokens) => {
            let access_token = tokens.access_token.clone();
            context.profiles.save(
                username,
                &SavedSession {
                    public_key_fingerprint: fingerprint,
                    tokens,
                },
            )?;
            Ok(access_token)
        }
        Err(error) => {
            context.profiles.delete(username)?;
            Err(anyhow!(
                "Could not refresh the public-key session. Run the command again to authenticate with the configured SSH key."
            )
            .context(error))
        }
    }
}

async fn public_key_login(
    context: &ClientContext,
    username: &str,
    key_path: &Path,
    public_key: &str,
) -> Result<LoginTokens> {
    let challenge = context
        .api
        .public_key_challenge(&PublicKeyChallengeRequest {
            username: username.to_owned(),
            public_key: public_key.to_owned(),
        })
        .await?;
    anyhow::ensure!(
        challenge.expires_at > unix_now()?,
        "public-key challenge expired"
    );
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&challenge.challenge)
        .context("decode public-key challenge")?;
    anyhow::ensure!(
        !challenge_bytes.is_empty() && challenge_bytes.len() <= 4096,
        "public-key challenge payload size is invalid"
    );
    let signature = sign_sshsig(key_path, &challenge_bytes)?;
    context
        .api
        .public_key_login(&PublicKeyLoginRequest {
            username: username.to_owned(),
            challenge_id: challenge.challenge_id,
            signature,
        })
        .await
}

fn public_key_fingerprint(public_key: &str) -> Result<String> {
    let public_key =
        ssh_key::PublicKey::from_openssh(public_key).context("parse configured SSH public key")?;
    Ok(public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

fn public_key(key_path: &Path) -> Result<String> {
    if key_path
        .extension()
        .is_some_and(|extension| extension == "pub")
    {
        return fs::read_to_string(key_path).context("read SSH public key");
    }
    let output = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(key_path)
        .stdin(Stdio::inherit())
        .output()
        .context("run ssh-keygen to extract public key")?;
    if !output.status.success() {
        bail!(
            "ssh-keygen could not read the public key from {}",
            key_path.display()
        );
    }
    String::from_utf8(output.stdout).context("ssh-keygen returned a non-UTF-8 public key")
}

fn sign_sshsig(key_path: &Path, challenge: &[u8]) -> Result<String> {
    let mut child = Command::new("ssh-keygen")
        .arg("-Y")
        .arg("sign")
        .arg("-f")
        .arg(key_path)
        .arg("-n")
        .arg("kmesh-login")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run ssh-keygen to sign the authentication challenge")?;
    child
        .stdin
        .take()
        .context("open ssh-keygen input")?
        .write_all(challenge)
        .context("write SSHSIG challenge")?;
    let output = child
        .wait_with_output()
        .context("wait for ssh-keygen signature")?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        bail!(
            "ssh-keygen could not sign the authentication challenge: {}",
            reason.trim()
        );
    }
    String::from_utf8(output.stdout).context("ssh-keygen returned a non-UTF-8 SSHSIG signature")
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests;
