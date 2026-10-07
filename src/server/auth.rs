use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sqlx::Row;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use uuid::Uuid;

use crate::identity::{self, USER_TOKEN_AUDIENCE};
use crate::protocol::{
    AccessTokenClaims, AuthCredential, LoginTokens, PublicKeyChallenge, PublicKeyChallengeRequest,
    PublicKeyLoginRequest, RefreshRequest,
};
use ssh_key::{HashAlg, PublicKey, SshSig};

use super::db::{row_uuid, unix_time};
use super::error::ApiError;
use super::{ServerState, hash_secret, new_secret};

const ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;
const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const SSH_CHALLENGE_TTL_SECS: i64 = 60;
const SSH_LOGIN_NAMESPACE: &str = "kmesh-login";
const AUTH_LIMIT_WINDOW_SECS: i64 = 60;
const AUTH_LIMIT_PER_IP: usize = 20;
const AUTH_LIMIT_IP_CAPACITY: usize = 4096;

#[derive(Default)]
pub(crate) struct AuthRateLimiter {
    attempts: tokio::sync::Mutex<HashMap<IpAddr, VecDeque<i64>>>,
}

impl AuthRateLimiter {
    pub async fn check(&self, ip: IpAddr) -> Result<(), ApiError> {
        let now = unix_time();
        let mut attempts = self.attempts.lock().await;
        attempts.retain(|_, times| {
            times
                .back()
                .is_some_and(|time| now - *time < AUTH_LIMIT_WINDOW_SECS)
        });
        if !attempts.contains_key(&ip) && attempts.len() >= AUTH_LIMIT_IP_CAPACITY {
            return Err(ApiError::rate_limited());
        }
        let times = attempts.entry(ip).or_default();
        while times
            .front()
            .is_some_and(|time| now - *time >= AUTH_LIMIT_WINDOW_SECS)
        {
            times.pop_front();
        }
        if times.len() >= AUTH_LIMIT_PER_IP {
            return Err(ApiError::rate_limited());
        }
        times.push_back(now);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedUser {
    pub user_id: String,
    pub credential: AuthCredential,
    pub expires_at: Option<i64>,
}

pub(crate) async fn public_key_challenge(
    State(state): State<ServerState>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<PublicKeyChallengeRequest>,
) -> Result<Json<PublicKeyChallenge>, ApiError> {
    state.inner.auth_rate_limiter.check(remote.ip()).await?;
    let username = normalize_username(&request.username)?;
    let canonical_key = canonical_ssh_key(&request.public_key)?;
    let fingerprint = ssh_fingerprint(&canonical_key)?;
    let row = sqlx::query(
        "SELECT u.id AS user_id, k.id AS key_id \
         FROM users u JOIN user_keys k ON k.user_id = u.id \
         WHERE u.username = ?1 AND u.enabled = 1 AND k.fingerprint = ?2 AND k.enabled = 1",
    )
    .bind(&username)
    .bind(fingerprint)
    .fetch_optional(&state.inner.db.pool)
    .await?;
    let (user_id, key_id): (Option<String>, Option<String>) = match row {
        Some(row) => (
            Some(row.try_get("user_id")?),
            Some(row_uuid(&row, "key_id")?.to_string()),
        ),
        None => (None, None),
    };
    let challenge_id = Uuid::new_v4();
    let now = unix_time();
    let expires_at = now + SSH_CHALLENGE_TTL_SECS;
    let signed_payload = ssh_challenge_payload(
        &state.inner.issuer,
        &username,
        challenge_id,
        expires_at,
        rand::random(),
    );
    let challenge = URL_SAFE_NO_PAD.encode(signed_payload);
    sqlx::query("DELETE FROM ssh_login_challenges WHERE expires_at < ?1")
        .bind(now)
        .execute(&state.inner.db.pool)
        .await?;
    sqlx::query(
        "INSERT INTO ssh_login_challenges(id, username, public_key, user_id, key_id, nonce, expires_at, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(challenge_id.to_string())
    .bind(username)
    .bind(canonical_key)
    .bind(user_id)
    .bind(key_id)
    .bind(&challenge)
    .bind(expires_at)
    .bind(now)
    .execute(&state.inner.db.pool)
    .await?;
    Ok(Json(PublicKeyChallenge {
        challenge_id,
        challenge,
        expires_at: expires_at as u64,
    }))
}

pub(crate) async fn public_key_login(
    State(state): State<ServerState>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<PublicKeyLoginRequest>,
) -> Result<Json<LoginTokens>, ApiError> {
    state.inner.auth_rate_limiter.check(remote.ip()).await?;
    if request.signature.len() > 16 * 1024 {
        return Err(ApiError::bad_request("signature is too large"));
    }
    let signature =
        SshSig::from_pem(request.signature.as_bytes()).map_err(|_| ApiError::unauthorized())?;
    let mut tx = state
        .inner
        .db
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(ApiError::from)?;
    let row = sqlx::query(
        "SELECT username, public_key, user_id, key_id, nonce, expires_at, consumed_at \
         FROM ssh_login_challenges WHERE id = ?1",
    )
    .bind(request.challenge_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from)?
    .ok_or_else(ApiError::unauthorized)?;

    let username: String = row.try_get("username").map_err(ApiError::from)?;
    let supplied_username = normalize_username(&request.username)?;
    let canonical_key: String = row.try_get("public_key").map_err(ApiError::from)?;
    let challenge: String = row.try_get("nonce").map_err(ApiError::from)?;
    let expires_at: i64 = row.try_get("expires_at").map_err(ApiError::from)?;
    let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(ApiError::from)?;
    if username != supplied_username || expires_at <= unix_time() || consumed_at.is_some() {
        return Err(ApiError::unauthorized());
    }
    let signed_payload = URL_SAFE_NO_PAD
        .decode(challenge.as_bytes())
        .map_err(|_| ApiError::unauthorized())?;
    let public_key =
        PublicKey::from_openssh(&canonical_key).map_err(|_| ApiError::unauthorized())?;
    public_key
        .verify(SSH_LOGIN_NAMESPACE, &signed_payload, &signature)
        .map_err(|_| ApiError::unauthorized())?;

    let user_id: Option<String> = row.try_get("user_id").map_err(ApiError::from)?;
    let key_id: Option<String> = row.try_get("key_id").map_err(ApiError::from)?;
    let (Some(user_id), Some(key_id)) = (user_id, key_id) else {
        return Err(ApiError::unauthorized());
    };
    let registered = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM users u JOIN user_keys k ON k.user_id = u.id \
         WHERE u.id = ?1 AND u.username = ?2 AND u.enabled = 1 AND k.id = ?3 \
           AND k.enabled = 1 AND k.public_key = ?4)",
    )
    .bind(&user_id)
    .bind(&username)
    .bind(&key_id)
    .bind(&canonical_key)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::from)?;
    if registered == 0 {
        return Err(ApiError::unauthorized());
    }
    let issued = tokens_for_new_session(&state, user_id.clone())?;
    let consumed = sqlx::query(
        "UPDATE ssh_login_challenges SET consumed_at = ?1 \
         WHERE id = ?2 AND consumed_at IS NULL AND expires_at >= ?1",
    )
    .bind(unix_time())
    .bind(request.challenge_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from)?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::unauthorized());
    }
    insert_auth_session(
        &mut tx,
        user_id,
        issued.session_id,
        &issued.tokens,
        unix_time(),
    )
    .await?;
    tx.commit().await.map_err(ApiError::from)?;
    Ok(Json(issued.tokens))
}

pub(crate) async fn refresh(
    State(state): State<ServerState>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<LoginTokens>, ApiError> {
    state.inner.auth_rate_limiter.check(remote.ip()).await?;
    if request.refresh_token.len() > 256 {
        return Err(ApiError::unauthorized());
    }
    let old_hash = hash_secret(&request.refresh_token);
    let now = unix_time();
    let new_refresh_token = new_secret();
    let new_hash = hash_secret(&new_refresh_token);
    let mut tx = state
        .inner
        .db
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(ApiError::from)?;

    let row = sqlx::query(
        "SELECT r.session_id, r.expires_at, r.consumed_at, r.revoked_at, \
                s.user_id, s.revoked_at AS session_revoked_at, u.enabled \
         FROM refresh_tokens r JOIN auth_sessions s ON s.id = r.session_id \
         JOIN users u ON u.id = s.user_id WHERE r.token_hash = ?1",
    )
    .bind(&old_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from)?
    .ok_or_else(ApiError::unauthorized)?;
    let session_id = row_uuid(&row, "session_id").map_err(ApiError::from)?;
    let user_id = row.try_get("user_id").map_err(ApiError::from)?;
    let expires_at: i64 = row.try_get("expires_at").map_err(ApiError::from)?;
    let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(ApiError::from)?;
    let refresh_revoked_at: Option<i64> = row.try_get("revoked_at").map_err(ApiError::from)?;
    let session_revoked_at: Option<i64> =
        row.try_get("session_revoked_at").map_err(ApiError::from)?;
    let enabled: i64 = row.try_get("enabled").map_err(ApiError::from)?;
    if consumed_at.is_some() {
        sqlx::query("UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?1) WHERE id = ?2")
            .bind(now)
            .bind(session_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from)?;
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE session_id = ?2",
        )
        .bind(now)
        .bind(session_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from)?;
        tx.commit().await.map_err(ApiError::from)?;
        return Err(ApiError::unauthorized());
    }
    if refresh_revoked_at.is_some()
        || session_revoked_at.is_some()
        || enabled != 1
        || expires_at <= now
    {
        tx.commit().await.map_err(ApiError::from)?;
        return Err(ApiError::unauthorized());
    }

    let access_expires_at = now + ACCESS_TOKEN_TTL_SECS;
    let refresh_expires_at = now + REFRESH_TOKEN_TTL_SECS;
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: state.inner.issuer.clone(),
        aud: USER_TOKEN_AUDIENCE.to_owned(),
        iat: now as u64,
        exp: access_expires_at as u64,
    };
    let access_token =
        identity::encode_user_access_token(&claims, &state.inner.keys.user_access.private_key_pem)
            .map_err(ApiError::from)?;
    let tokens = LoginTokens {
        access_token,
        refresh_token: new_refresh_token,
        access_expires_at: access_expires_at as u64,
        refresh_expires_at: refresh_expires_at as u64,
    };
    let update = sqlx::query(
        "UPDATE refresh_tokens SET consumed_at = ?1, replaced_by_hash = ?2 \
         WHERE token_hash = ?3 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(&new_hash)
    .bind(&old_hash)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from)?;
    if update.rows_affected() != 1 {
        return Err(ApiError::unauthorized());
    }
    sqlx::query(
        "INSERT INTO refresh_tokens(token_hash, session_id, expires_at) VALUES (?1, ?2, ?3)",
    )
    .bind(&new_hash)
    .bind(session_id.to_string())
    .bind(refresh_expires_at)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from)?;
    sqlx::query(
        "UPDATE auth_sessions SET access_expires_at = ?1, refresh_expires_at = ?2 WHERE id = ?3",
    )
    .bind(access_expires_at)
    .bind(refresh_expires_at)
    .bind(session_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from)?;
    tx.commit().await.map_err(ApiError::from)?;
    Ok(Json(tokens))
}

pub(crate) async fn logout(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<axum::http::StatusCode, ApiError> {
    let user = authenticate(&state, &headers).await?;
    let AuthCredential::Session(session_id) = user.credential else {
        return Err(ApiError::bad_request(
            "API tokens are revoked through admin tokens revoke",
        ));
    };
    let now = unix_time();
    let mut tx = state.inner.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?1) WHERE id = ?2 AND user_id = ?3")
        .bind(now)
        .bind(session_id.to_string())
    .bind(&user.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE session_id = ?2",
    )
    .bind(now)
    .bind(session_id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub(crate) async fn authenticate(
    state: &ServerState,
    headers: &HeaderMap,
) -> Result<AuthenticatedUser, ApiError> {
    let token = bearer_token(headers)?;
    if let Ok(claims) = identity::decode_user_access_token(
        token,
        &state.inner.keys.user_access.public_key_pem,
        &state.inner.issuer,
    ) {
        let active = state
            .inner
            .db
            .is_session_active(&claims.sub, claims.sid)
            .await
            .map_err(ApiError::from)?;
        if !active {
            return Err(ApiError::unauthorized());
        }
        return Ok(AuthenticatedUser {
            user_id: claims.sub,
            credential: AuthCredential::Session(claims.sid),
            expires_at: Some(claims.exp as i64),
        });
    }

    let claims = identity::decode_api_token(
        token,
        &state.inner.keys.user_access.public_key_pem,
        &state.inner.issuer,
    )
    .map_err(|_| ApiError::unauthorized())?;
    let token_hash = hash_secret(token);
    let expires_at = claims.exp.map(|expires_at| expires_at as i64);
    let active = state
        .inner
        .db
        .is_api_token_active(&claims.sub, claims.jti, expires_at, &token_hash)
        .await
        .map_err(ApiError::from)?;
    if !active {
        return Err(ApiError::unauthorized());
    }
    Ok(AuthenticatedUser {
        user_id: claims.sub,
        credential: AuthCredential::ApiToken(claims.jti),
        expires_at,
    })
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    value
        .strip_prefix("Bearer ")
        .ok_or_else(ApiError::unauthorized)
}

struct IssuedTokens {
    session_id: Uuid,
    tokens: LoginTokens,
}

fn tokens_for_new_session(state: &ServerState, user_id: String) -> Result<IssuedTokens, ApiError> {
    let now = unix_time();
    let session_id = Uuid::new_v4();
    let refresh_token = new_secret();
    let access_expires_at = now + ACCESS_TOKEN_TTL_SECS;
    let refresh_expires_at = now + REFRESH_TOKEN_TTL_SECS;
    let claims = AccessTokenClaims {
        sub: user_id.clone(),
        sid: session_id,
        iss: state.inner.issuer.clone(),
        aud: USER_TOKEN_AUDIENCE.to_owned(),
        iat: now as u64,
        exp: access_expires_at as u64,
    };
    let access_token =
        identity::encode_user_access_token(&claims, &state.inner.keys.user_access.private_key_pem)
            .map_err(ApiError::from)?;
    Ok(IssuedTokens {
        session_id,
        tokens: LoginTokens {
            access_token,
            refresh_token,
            access_expires_at: access_expires_at as u64,
            refresh_expires_at: refresh_expires_at as u64,
        },
    })
}

async fn insert_auth_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: String,
    session_id: Uuid,
    tokens: &LoginTokens,
    now: i64,
) -> Result<(), ApiError> {
    let refresh_hash = hash_secret(&tokens.refresh_token);
    sqlx::query(
        "INSERT INTO auth_sessions(id, user_id, created_at, access_expires_at, refresh_expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(session_id.to_string())
    .bind(user_id)
    .bind(now)
    .bind(tokens.access_expires_at as i64)
    .bind(tokens.refresh_expires_at as i64)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO refresh_tokens(token_hash, session_id, expires_at) VALUES (?1, ?2, ?3)",
    )
    .bind(refresh_hash)
    .bind(session_id.to_string())
    .bind(tokens.refresh_expires_at as i64)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) fn normalize_username(username: &str) -> Result<String, ApiError> {
    let username = username.trim();
    if username.is_empty()
        || !username.is_ascii()
        || username.len() > 64
        || username.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "username must be 1 to 64 printable ASCII bytes",
        ));
    }
    Ok(username.to_ascii_lowercase())
}

pub(crate) fn canonical_ssh_key(value: &str) -> Result<String, ApiError> {
    if value.len() > 16 * 1024 {
        return Err(ApiError::bad_request("SSH public key is too large"));
    }
    let mut key = PublicKey::from_openssh(value)
        .map_err(|_| ApiError::bad_request("invalid SSH public key"))?;
    key.set_comment("");
    let canonical = key
        .to_openssh()
        .map_err(|_| ApiError::bad_request("invalid SSH public key"))?;
    let algorithm = canonical
        .split_whitespace()
        .next()
        .ok_or_else(|| ApiError::bad_request("invalid SSH public key"))?;
    if !matches!(
        algorithm,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
    ) {
        return Err(ApiError::bad_request(
            "SSH public key algorithm is unsupported",
        ));
    }
    Ok(canonical)
}

pub(crate) fn ssh_fingerprint(public_key: &str) -> Result<String, ApiError> {
    let key = PublicKey::from_openssh(public_key)
        .map_err(|_| ApiError::bad_request("invalid SSH public key"))?;
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
}

fn ssh_challenge_payload(
    issuer: &str,
    username: &str,
    challenge_id: Uuid,
    expires_at: i64,
    nonce: [u8; 32],
) -> Vec<u8> {
    let mut payload = b"kmesh-login-challenge-v1\0".to_vec();
    append_field(&mut payload, b"login");
    append_field(&mut payload, issuer.as_bytes());
    append_field(&mut payload, username.as_bytes());
    append_field(&mut payload, challenge_id.as_bytes());
    payload.extend_from_slice(&expires_at.to_be_bytes());
    append_field(&mut payload, &nonce);
    payload
}

fn append_field(payload: &mut Vec<u8>, value: &[u8]) {
    let length = value.len() as u32;
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(value);
}

#[cfg(test)]
mod tests;
