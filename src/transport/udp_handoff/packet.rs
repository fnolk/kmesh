//! Signed mode-2 datagram format and verification.

use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

use super::{PunchIdentity, PunchRole};

const PACKET_MAGIC: &[u8; 8] = b"KMSHPN01";
const PACKET_HEADER_LEN: usize = 92;
const PACKET_SIGNATURE_LEN: usize = 64;
pub(super) const PACKET_LEN: usize = PACKET_HEADER_LEN + PACKET_SIGNATURE_LEN;

pub(super) struct Packet {
    pub(super) kind: PacketKind,
    pub(super) index: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PacketKind {
    Probe = 1,
    Offer = 2,
    Select = 3,
    Confirm = 4,
}

impl PacketKind {
    fn parse(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Probe),
            2 => Some(Self::Offer),
            3 => Some(Self::Select),
            4 => Some(Self::Confirm),
            _ => None,
        }
    }
}
pub(super) fn encode_packet(
    secret_key: &SecretKey,
    identity: PunchIdentity,
    role: PunchRole,
    kind: PacketKind,
    index: u16,
) -> [u8; PACKET_LEN] {
    let mut bytes = [0u8; PACKET_LEN];
    bytes[..8].copy_from_slice(PACKET_MAGIC);
    bytes[8..24].copy_from_slice(identity.session_id.as_bytes());
    bytes[24..56].copy_from_slice(identity.target_id.as_bytes());
    bytes[56..88].copy_from_slice(identity.client_id.as_bytes());
    bytes[88] = role.wire();
    bytes[89] = kind as u8;
    bytes[90..92].copy_from_slice(&index.to_be_bytes());
    let signature = secret_key.sign(&bytes[..PACKET_HEADER_LEN]);
    bytes[PACKET_HEADER_LEN..].copy_from_slice(&signature.to_bytes());
    bytes
}

pub(super) fn decode_packet(
    bytes: &[u8],
    identity: PunchIdentity,
    peer_id: EndpointId,
    expected_role: PunchRole,
) -> Option<Packet> {
    if bytes.len() != PACKET_LEN
        || &bytes[..8] != PACKET_MAGIC
        || &bytes[8..24] != identity.session_id.as_bytes()
        || &bytes[24..56] != identity.target_id.as_bytes()
        || &bytes[56..88] != identity.client_id.as_bytes()
        || bytes[88] != expected_role.wire()
    {
        return None;
    }
    let kind = PacketKind::parse(bytes[89])?;
    let index = u16::from_be_bytes(bytes[90..92].try_into().ok()?);
    let signature = iroh::Signature::try_from(&bytes[PACKET_HEADER_LEN..]).ok()?;
    peer_id
        .verify(&bytes[..PACKET_HEADER_LEN], &signature)
        .ok()?;
    Some(Packet { kind, index })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn punch_signature_binds_session_role_and_selection_index() {
        let target_key = SecretKey::generate();
        let client_key = SecretKey::generate();
        let identity = PunchIdentity {
            session_id: Uuid::new_v4(),
            target_id: target_key.public(),
            client_id: client_key.public(),
        };
        let packet = encode_packet(
            &client_key,
            identity,
            PunchRole::Client,
            PacketKind::Select,
            17,
        );
        assert!(matches!(
            decode_packet(&packet, identity, identity.client_id, PunchRole::Client),
            Some(Packet {
                kind: PacketKind::Select,
                index: 17
            })
        ));

        let mut wrong_session = packet;
        wrong_session[8] ^= 1;
        assert!(
            decode_packet(
                &wrong_session,
                identity,
                identity.client_id,
                PunchRole::Client
            )
            .is_none()
        );

        let mut wrong_role = packet;
        wrong_role[88] = PunchRole::Target.wire();
        assert!(
            decode_packet(&wrong_role, identity, identity.client_id, PunchRole::Client).is_none()
        );

        let mut wrong_index = packet;
        wrong_index[91] ^= 1;
        assert!(
            decode_packet(
                &wrong_index,
                identity,
                identity.client_id,
                PunchRole::Client
            )
            .is_none()
        );
        assert!(decode_packet(&packet, identity, identity.target_id, PunchRole::Client).is_none());
    }
}
