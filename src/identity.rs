use crate::protocol::{AccessTokenClaims, RouteMode, TunnelTicketClaims};
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

/// Canonical bytes the enrolled target identity signs before the server registers a per-session
/// Iroh data endpoint. The persistent endpoint key proves which device authorized this identity;
/// the data endpoint key remains session-scoped.
pub fn agent_session_identity_payload(
    session_id: uuid::Uuid,
    target_id: uuid::Uuid,
    route_mode: RouteMode,
    target_data_endpoint_id: &iroh::EndpointId,
    expires_at: i64,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"kmesh/agent-session-identity/1\0";
    let mut payload = Vec::with_capacity(DOMAIN.len() + 16 + 16 + 1 + 32 + 8);
    payload.extend_from_slice(DOMAIN);
    payload.extend_from_slice(session_id.as_bytes());
    payload.extend_from_slice(target_id.as_bytes());
    payload.push(match route_mode {
        RouteMode::PrivateDirect => 1,
        RouteMode::PublicDirect => 2,
        RouteMode::PrivateRelay => 3,
    });
    payload.extend_from_slice(target_data_endpoint_id.as_bytes());
    payload.extend_from_slice(&expires_at.to_be_bytes());
    payload
}

pub fn verify_agent_session_identity(
    stable_device_endpoint_id: &str,
    session_id: uuid::Uuid,
    target_id: uuid::Uuid,
    route_mode: RouteMode,
    target_data_endpoint_id: &str,
    expires_at: i64,
    signature: &[u8],
) -> Result<()> {
    let stable_device_endpoint_id = stable_device_endpoint_id
        .parse::<iroh::EndpointId>()
        .context("parse enrolled device EndpointId")?;
    let target_data_endpoint_id = target_data_endpoint_id
        .parse::<iroh::EndpointId>()
        .context("parse per-session target EndpointId")?;
    let signature = iroh::Signature::try_from(signature).context("parse device signature")?;
    let payload = agent_session_identity_payload(
        session_id,
        target_id,
        route_mode,
        &target_data_endpoint_id,
        expires_at,
    );
    stable_device_endpoint_id
        .verify(&payload, &signature)
        .context("verify per-session endpoint identity with enrolled device key")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_session_identity_is_bound_to_device_session_target_mode_endpoint_and_expiry() {
        let device_key = iroh::SecretKey::generate();
        let data_key = iroh::SecretKey::generate();
        let session_id = uuid::Uuid::new_v4();
        let target_id = uuid::Uuid::new_v4();
        let expires_at = 1_800_000_000;
        let mode_offset = b"kmesh/agent-session-identity/1\0".len() + 32;
        for (mode, tag) in [
            (RouteMode::PrivateDirect, 1),
            (RouteMode::PublicDirect, 2),
            (RouteMode::PrivateRelay, 3),
        ] {
            assert_eq!(
                agent_session_identity_payload(
                    session_id,
                    target_id,
                    mode,
                    &data_key.public(),
                    expires_at,
                )[mode_offset],
                tag
            );
        }
        let signature = device_key
            .sign(&agent_session_identity_payload(
                session_id,
                target_id,
                RouteMode::PrivateDirect,
                &data_key.public(),
                expires_at,
            ))
            .to_bytes();

        verify_agent_session_identity(
            &device_key.public().to_string(),
            session_id,
            target_id,
            RouteMode::PrivateDirect,
            &data_key.public().to_string(),
            expires_at,
            &signature,
        )
        .expect("valid per-session identity signature");
        assert!(
            verify_agent_session_identity(
                &device_key.public().to_string(),
                uuid::Uuid::new_v4(),
                target_id,
                RouteMode::PrivateDirect,
                &data_key.public().to_string(),
                expires_at,
                &signature,
            )
            .is_err()
        );
        let other_device_key = iroh::SecretKey::generate();
        assert!(
            verify_agent_session_identity(
                &other_device_key.public().to_string(),
                session_id,
                target_id,
                RouteMode::PrivateDirect,
                &data_key.public().to_string(),
                expires_at,
                &signature,
            )
            .is_err()
        );
        let other_data_key = iroh::SecretKey::generate();
        assert!(
            verify_agent_session_identity(
                &device_key.public().to_string(),
                session_id,
                target_id,
                RouteMode::PrivateDirect,
                &other_data_key.public().to_string(),
                expires_at,
                &signature,
            )
            .is_err()
        );
        assert!(
            verify_agent_session_identity(
                &device_key.public().to_string(),
                session_id,
                target_id,
                RouteMode::PublicDirect,
                &data_key.public().to_string(),
                expires_at,
                &signature,
            )
            .is_err()
        );
        assert!(
            verify_agent_session_identity(
                &device_key.public().to_string(),
                session_id,
                target_id,
                RouteMode::PrivateRelay,
                &data_key.public().to_string(),
                expires_at,
                &signature,
            )
            .is_err()
        );
        assert!(
            verify_agent_session_identity(
                &device_key.public().to_string(),
                session_id,
                target_id,
                RouteMode::PrivateDirect,
                &data_key.public().to_string(),
                expires_at + 1,
                &signature,
            )
            .is_err()
        );
    }
}
