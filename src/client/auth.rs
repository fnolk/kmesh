use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rpassword::prompt_password;

use crate::protocol::{
    LoginTokens, PasswordLoginRequest, PublicKeyChallengeRequest, PublicKeyLoginRequest,
    RefreshRequest,
};

use super::{
    ClientContext,
    cli::{LoginArgs, LoginMethod},
    profile::{SavedLogin, normalize_username},
};

pub async fn login(context: &ClientContext, args: &LoginArgs) -> Result<()> {
    let username = normalize_username(&args.username);
    anyhow::ensure!(!username.is_empty(), "username is empty");
    let tokens = match args.method {
        LoginMethod::Password => {
            let password = read_password("请输入密码：", args.password_stdin)?;
            context
                .api
                .password_login(&PasswordLoginRequest {
                    username: username.clone(),
                    password,
                })
                .await?
        }
        LoginMethod::PublicKey => {
            let key_path = args.key.as_deref().context(
                "public-key login requires --key pointing to a private key or its .pub file",
            )?;
            public_key_login(context, &username, key_path).await?
        }
    };
    save_login(context, &username, tokens)
}

pub fn read_password(prompt: &str, stdin: bool) -> Result<String> {
    if !stdin {
        return prompt_password(prompt).context("read password");
    }
    use std::io::IsTerminal;
    anyhow::ensure!(
        !std::io::stdin().is_terminal(),
        "--password-stdin requires piped stdin"
    );
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .context("read password from stdin")?;
    Ok(password.trim_end_matches(['\r', '\n']).to_owned())
}

async fn public_key_login(
    context: &ClientContext,
    username: &str,
    key_path: &Path,
) -> Result<LoginTokens> {
    let public_key = public_key(key_path)?;
    let challenge = context
        .api
        .public_key_challenge(&PublicKeyChallengeRequest {
            username: username.to_owned(),
            public_key,
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
        .context("run ssh-keygen to sign the login challenge")?;
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
            "ssh-keygen could not sign the login challenge: {}",
            reason.trim()
        );
    }
    String::from_utf8(output.stdout).context("ssh-keygen returned a non-UTF-8 SSHSIG signature")
}

pub async fn valid_access_token(context: &ClientContext) -> Result<String> {
    let username = context.profiles.active_user()?;
    valid_access_token_for_user(context, &username).await
}

async fn valid_access_token_for_user(context: &ClientContext, username: &str) -> Result<String> {
    let saved = context
        .profiles
        .load(username)?
        .context("请先运行 kmesh login")?;
    let now = unix_now()?;
    if saved.tokens.access_expires_at > now.saturating_add(30) {
        return Ok(saved.tokens.access_token);
    }
    let profiles = context.profiles.clone();
    let _lock = tokio::task::spawn_blocking(move || profiles.lock_refresh())
        .await
        .context("refresh lock task failed")??;
    let mut saved = context
        .profiles
        .load(username)?
        .context("请先运行 kmesh login")?;
    let now = unix_now()?;
    if saved.tokens.access_expires_at > now.saturating_add(30) {
        return Ok(saved.tokens.access_token);
    }
    if saved.tokens.refresh_expires_at <= now {
        context.profiles.delete(username)?;
        context.profiles.clear_active_user_if(username)?;
        bail!("登录已过期，请运行 kmesh login");
    }

    match context
        .api
        .refresh(&RefreshRequest {
            refresh_token: saved.tokens.refresh_token.clone(),
        })
        .await
    {
        Ok(tokens) => {
            saved.tokens = tokens;
            context.profiles.save(&saved)?;
            Ok(saved.tokens.access_token)
        }
        Err(error) => {
            context.profiles.delete(username)?;
            context.profiles.clear_active_user_if(username)?;
            Err(anyhow!("刷新凭据的结果无法确认，请重新运行 kmesh login").context(error))
        }
    }
}

pub async fn logout(context: &ClientContext) -> Result<()> {
    let username = context.profiles.active_user()?;
    let token = valid_access_token_for_user(context, &username).await?;
    context.api.logout(&token).await?;
    let _lock = context.profiles.lock_refresh()?;
    context.profiles.delete(&username)?;
    context.profiles.clear_active_user_if(&username)?;
    Ok(())
}

fn save_login(context: &ClientContext, username: &str, tokens: LoginTokens) -> Result<()> {
    let _lock = context.profiles.lock_refresh()?;
    context.profiles.save(&SavedLogin {
        server_url: context.config.server_url.clone(),
        profile: context.config.profile.trim().to_lowercase(),
        username: username.to_owned(),
        tokens,
    })?;
    context.profiles.set_active_user(username)
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests;
