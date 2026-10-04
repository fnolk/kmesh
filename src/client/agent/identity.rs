use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::SecretKey;

pub(super) fn encode_secret_key(secret_key: &SecretKey) -> String {
    URL_SAFE_NO_PAD.encode(secret_key.to_bytes())
}

pub(super) fn decode_secret_key(encoded: &str) -> Result<SecretKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode saved target Iroh secret key")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("saved target Iroh secret key must contain 32 bytes"))?;
    Ok(SecretKey::from_bytes(&bytes))
}
