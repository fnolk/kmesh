mod admin;
mod auth;
mod control;
mod db;
mod error;
mod http;
mod iroh;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use db::Database;
use identity::{Ed25519PemKeypair, TokenKeySet};
use rand::random;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::identity;

pub use control::OnlineAgent;
pub use http::router;
pub use iroh::IrohServer;

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub data_dir: PathBuf,
    pub issuer: String,
    pub bind: SocketAddr,
    pub qad_bind: SocketAddr,
    pub disable_private_relay: bool,
}

#[derive(Clone)]
pub struct ServerState {
    pub(crate) inner: Arc<ServerInner>,
}

pub(crate) struct ServerInner {
    pub db: Database,
    pub issuer: String,
    pub keys: TokenKeySet,
    pub auth_rate_limiter: auth::AuthRateLimiter,
    pub online_agents: RwLock<std::collections::HashMap<Uuid, OnlineAgent>>,
    pub tunnels: RwLock<std::collections::HashMap<Uuid, Arc<control::TunnelRuntime>>>,
    pub transport_info: RwLock<crate::protocol::TransportInfo>,
}

/// Create the database, token keys, initial management account, and initial API token once.
pub async fn initialize(
    data_dir: impl AsRef<Path>,
    admin_username: &str,
    issuer: &str,
) -> Result<Option<String>> {
    let data_dir = data_dir.as_ref();
    if issuer.trim().is_empty() || issuer.len() > 512 {
        bail!("issuer must be non-empty");
    }
    let admin_username = auth::normalize_username(admin_username)?;
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("create server data directory {}", data_dir.display()))?;
    #[cfg(unix)]
    set_private_dir(data_dir)?;

    let lock_path = data_dir.join("initialize.lock");
    let lock = open_private_file(&lock_path)?;
    use fs2::FileExt;
    lock.lock_exclusive()
        .context("lock server initialization")?;

    let db = Database::open(data_dir.join("server.sqlite3")).await?;
    db.apply_schema().await?;
    let user_count = db.user_count().await?;
    let key_path = data_dir.join("token-keys.json");
    if key_path.exists() {
        #[cfg(unix)]
        set_private_file(&key_path)?;
    } else if user_count > 0 {
        bail!("initialized database is missing persistent token keys");
    } else {
        let keys = identity::generate_token_key_set().context("generate server token keys")?;
        write_private_atomically(&key_path, &serde_json::to_vec(&PersistedKeys::from(&keys))?)?;
    }
    let initial_api_token = if user_count == 0 {
        Some(new_api_token())
    } else {
        None
    };
    db.initialize(
        issuer,
        &admin_username,
        initial_api_token.as_deref().map(hash_secret),
    )
    .await?;
    FileExt::unlock(&lock).context("unlock server initialization")?;
    Ok(initial_api_token)
}

/// Run the HTTPS API, embedded Iroh relay, and Iroh QAD using persistent server state.
pub async fn run(options: ServerOptions) -> Result<()> {
    if options.issuer.trim().is_empty() || options.issuer.len() > 512 {
        bail!("configured issuer is invalid");
    }
    let db = Database::open(options.data_dir.join("server.sqlite3")).await?;
    db.apply_schema().await?;
    let stored_issuer = db
        .setting("issuer")
        .await?
        .context("server is not initialized")?;
    if stored_issuer != options.issuer {
        bail!("configured issuer does not match initialized server");
    }
    let key_bytes = std::fs::read(options.data_dir.join("token-keys.json"))
        .context("read persistent server token keys")?;
    let keys = PersistedKeys::from_slice(&key_bytes)?.into_token_keys();
    validate_token_keys(&keys, &options.issuer)?;
    sqlx::query(
        "UPDATE tunnel_sessions SET status = 'closed', closed_at = unixepoch() \
         WHERE status IN ('pending', 'active')",
    )
    .execute(&db.pool)
    .await
    .context("close sessions from the previous server process")?;
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|error| anyhow::anyhow!("install rustls crypto provider: {error:?}"))?;
    }

    let state = ServerState {
        inner: Arc::new(ServerInner {
            db,
            issuer: options.issuer.clone(),
            keys,
            auth_rate_limiter: auth::AuthRateLimiter::default(),
            online_agents: RwLock::new(std::collections::HashMap::new()),
            tunnels: RwLock::new(std::collections::HashMap::new()),
            transport_info: RwLock::new(crate::protocol::TransportInfo {
                private_relay_url: (!options.disable_private_relay).then(|| options.issuer.clone()),
                qad_port: options.qad_bind.port(),
            }),
        }),
    };
    let relay_access = (!options.disable_private_relay)
        .then(|| Arc::new(state.clone()) as Arc<dyn iroh_relay::server::DynAccessControl>);
    let server = iroh::listen_and_serve(
        router(state.clone()),
        relay_access,
        options.bind,
        options.qad_bind,
    )
    .await?;
    state.inner.transport_info.write().await.qad_port = server.qad_addr().port();
    tracing::info!(https = %server.https_addr(), qad = %server.qad_addr(), "kmesh HTTPS, Iroh relay, and QAD listeners started");
    server.run_until_shutdown().await
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedKeys {
    user_access_private_key_pem: String,
    user_access_public_key_pem: String,
    tunnel_ticket_private_key_pem: String,
    tunnel_ticket_public_key_pem: String,
}

impl From<&TokenKeySet> for PersistedKeys {
    fn from(keys: &TokenKeySet) -> Self {
        Self {
            user_access_private_key_pem: keys.user_access.private_key_pem.clone(),
            user_access_public_key_pem: keys.user_access.public_key_pem.clone(),
            tunnel_ticket_private_key_pem: keys.tunnel_ticket.private_key_pem.clone(),
            tunnel_ticket_public_key_pem: keys.tunnel_ticket.public_key_pem.clone(),
        }
    }
}

impl PersistedKeys {
    fn from_slice(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).context("decode persistent server token keys")
    }

    fn into_token_keys(self) -> TokenKeySet {
        TokenKeySet {
            user_access: Ed25519PemKeypair {
                private_key_pem: self.user_access_private_key_pem,
                public_key_pem: self.user_access_public_key_pem,
            },
            tunnel_ticket: Ed25519PemKeypair {
                private_key_pem: self.tunnel_ticket_private_key_pem,
                public_key_pem: self.tunnel_ticket_public_key_pem,
            },
        }
    }
}

fn validate_token_keys(keys: &TokenKeySet, issuer: &str) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    let claims = crate::protocol::AccessTokenClaims {
        sub: Uuid::new_v4(),
        sid: Uuid::new_v4(),
        iss: issuer.to_owned(),
        aud: identity::USER_TOKEN_AUDIENCE.to_owned(),
        iat: now,
        exp: now + 60,
    };
    let token = identity::encode_user_access_token(&claims, &keys.user_access.private_key_pem)
        .context("validate user token signing key")?;
    identity::decode_user_access_token(&token, &keys.user_access.public_key_pem, issuer)
        .context("validate user token key pair")?;
    let ticket_claims = crate::protocol::TunnelTicketClaims {
        session_id: Uuid::new_v4(),
        user_id: claims.sub,
        login_session_id: claims.sid,
        target_id: Uuid::new_v4(),
        client_endpoint_id: String::new(),
        target_endpoint_id: String::new(),
        route_mode: crate::protocol::RouteMode::PrivateRelay,
        iss: issuer.to_owned(),
        aud: identity::TUNNEL_TICKET_AUDIENCE.to_owned(),
        iat: now,
        exp: now + 60,
    };
    let ticket =
        identity::encode_tunnel_ticket(&ticket_claims, &keys.tunnel_ticket.private_key_pem)
            .context("validate tunnel ticket signing key")?;
    identity::decode_tunnel_ticket(&ticket, &keys.tunnel_ticket.public_key_pem, issuer)
        .context("validate tunnel ticket key pair")?;
    Ok(())
}

pub(crate) fn hash_secret(value: &str) -> String {
    hex_digest(Sha256::digest(value.as_bytes()).as_slice())
}

pub(crate) fn new_secret() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random::<[u8; 32]>())
}

pub(crate) fn new_api_token() -> String {
    format!("kmesh_{}", new_secret())
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn open_private_file(path: &Path) -> Result<std::fs::File> {
    use std::fs::OpenOptions;
    let mut options = OpenOptions::new();
    options.create(true).append(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("open private file {}", path.display()))
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure data directory {}", path.display()))
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("secure private file {}", path.display()))
}

fn write_private_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    let temp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp_path)
        .with_context(|| format!("create private key file {}", temp_path.display()))?;
    file.write_all(contents)
        .context("write server token keys")?;
    file.sync_all().context("sync server token keys")?;
    std::fs::rename(&temp_path, path)
        .with_context(|| format!("move server token keys into place at {}", path.display()))?;
    Ok(())
}
