use crate::protocol::{AccessTokenClaims, TunnelTicketClaims};
use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rcgen::{KeyPair, PKCS_ED25519};
use serde::de::DeserializeOwned;

pub const USER_TOKEN_AUDIENCE: &str = "kmesh-user";
pub const TUNNEL_TICKET_AUDIENCE: &str = "kmesh-tunnel";

#[derive(Clone, Debug)]
pub struct Ed25519PemKeypair {
    pub private_key_pem: String,
    pub public_key_pem: String,
}

#[derive(Clone, Debug)]
pub struct TokenKeySet {
    pub user_access: Ed25519PemKeypair,
    pub tunnel_ticket: Ed25519PemKeypair,
}

pub fn generate_ed25519_keypair() -> Result<Ed25519PemKeypair> {
    let key = KeyPair::generate_for(&PKCS_ED25519).context("generate Ed25519 key")?;
    Ok(Ed25519PemKeypair {
        private_key_pem: key.serialize_pem(),
        public_key_pem: key.public_key_pem(),
    })
}

pub fn generate_token_key_set() -> Result<TokenKeySet> {
    Ok(TokenKeySet {
        user_access: generate_ed25519_keypair()?,
        tunnel_ticket: generate_ed25519_keypair()?,
    })
}

pub fn encode_user_access_token(
    claims: &AccessTokenClaims,
    private_key_pem: &str,
) -> Result<String> {
    anyhow::ensure!(
        claims.aud == USER_TOKEN_AUDIENCE,
        "incorrect user token audience"
    );
    let key = EncodingKey::from_ed_pem(private_key_pem.as_bytes())
        .context("load user JWT signing key")?;
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("JWT".to_owned());
    encode(&header, claims, &key).context("encode user access token")
}

pub fn decode_user_access_token(
    token: &str,
    public_key_pem: &str,
    expected_issuer: &str,
) -> Result<AccessTokenClaims> {
    decode_claims(
        token,
        public_key_pem,
        USER_TOKEN_AUDIENCE,
        expected_issuer,
        0,
    )
}

pub fn encode_tunnel_ticket(claims: &TunnelTicketClaims, private_key_pem: &str) -> Result<String> {
    anyhow::ensure!(
        claims.aud == TUNNEL_TICKET_AUDIENCE,
        "incorrect tunnel ticket audience"
    );
    let key = EncodingKey::from_ed_pem(private_key_pem.as_bytes())
        .context("load tunnel ticket signing key")?;
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("JWT".to_owned());
    encode(&header, claims, &key).context("encode tunnel ticket")
}

pub fn decode_tunnel_ticket(
    token: &str,
    public_key_pem: &str,
    expected_issuer: &str,
) -> Result<TunnelTicketClaims> {
    decode_claims(
        token,
        public_key_pem,
        TUNNEL_TICKET_AUDIENCE,
        expected_issuer,
        2,
    )
}

fn decode_claims<T: DeserializeOwned>(
    token: &str,
    public_key_pem: &str,
    audience: &str,
    issuer: &str,
    leeway_secs: u64,
) -> Result<T> {
    let key = DecodingKey::from_ed_pem(public_key_pem.as_bytes())
        .context("load Ed25519 JWT verification key")?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iat", "aud", "iss"]);
    validation.leeway = leeway_secs;
    decode::<T>(token, &key, &validation)
        .map(|data| data.claims)
        .context("verify Ed25519 JWT")
}
