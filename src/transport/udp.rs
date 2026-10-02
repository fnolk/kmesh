use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::Sha256;
use tokio::net::UdpSocket;
use tokio::time::{Instant, interval_at, sleep_until};
use uuid::Uuid;

use crate::config::StunConfig;
use crate::transport::TransportError;
use crate::transport::stun::{gather_mapping, resolve_servers, same_address_family};

const PROBE_MAGIC: &[u8; 4] = b"KMP1";
const PROBE_REQUEST: u8 = 1;
const PROBE_ACK: u8 = 2;
const PROBE_NONCE_LEN: usize = 16;
const PROBE_MAC_LEN: usize = 32;
const PROBE_HEADER_LEN: usize = 4 + 16 + 1 + PROBE_NONCE_LEN;
const PROBE_PACKET_LEN: usize = PROBE_HEADER_LEN + PROBE_MAC_LEN;
const PROBE_PERIOD: Duration = Duration::from_millis(100);
const PROBE_SETTLE: Duration = Duration::from_millis(250);

type HmacSha256 = Hmac<Sha256>;

pub struct UdpAttempt {
    socket: UdpSocket,
    config: StunConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    pub peer_addr: SocketAddr,
}

#[derive(Debug)]
pub struct StunMappingObservation {
    pub local_socket: SocketAddr,
    pub destination: SocketAddr,
    pub outcome: Result<SocketAddr, TransportError>,
    pub rtt: Duration,
}

impl UdpAttempt {
    pub async fn bind(config: StunConfig) -> Result<Self, TransportError> {
        if config.probe_timeout_millis == 0 {
            return Err(TransportError::Configuration(
                "probe timeout must be greater than zero".to_owned(),
            ));
        }
        let socket = UdpSocket::bind(config.udp_bind_address)
            .await
            .map_err(TransportError::Network)?;
        Ok(Self { socket, config })
    }

    pub async fn gather(&mut self) -> Result<Vec<SocketAddr>, TransportError> {
        let local = self.socket.local_addr().map_err(TransportError::Network)?;
        let mut candidates = local_candidates(local)?;
        let servers = resolve_servers(&self.config).await?;
        for server in servers {
            if same_address_family(local, server.ip()) {
                candidates.push(self.observe_stun_mapping(local, server).await.outcome?);
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        Ok(candidates)
    }

    /// Measure STUN mappings to several destinations on this attempt's UDP socket.
    pub async fn observe_stun_mappings(
        &mut self,
        destinations: &[SocketAddr],
    ) -> Result<Vec<StunMappingObservation>, TransportError> {
        let local_socket = self.socket.local_addr().map_err(TransportError::Network)?;
        let mut observations = Vec::with_capacity(destinations.len());
        for destination in destinations {
            if !same_address_family(local_socket, destination.ip()) {
                continue;
            }
            observations.push(self.observe_stun_mapping(local_socket, *destination).await);
        }
        Ok(observations)
    }

    async fn observe_stun_mapping(
        &self,
        local_socket: SocketAddr,
        destination: SocketAddr,
    ) -> StunMappingObservation {
        let started = Instant::now();
        let outcome = gather_mapping(&self.socket, destination).await;
        StunMappingObservation {
            local_socket,
            destination,
            outcome,
            rtt: started.elapsed(),
        }
    }

    /// Perform an authenticated, bounded UDP connectivity probe over this attempt's socket.
    pub async fn probe(
        &mut self,
        session_id: Uuid,
        probe_token: [u8; 32],
        remote_candidates: &[SocketAddr],
        timeout: Duration,
    ) -> Result<ProbeResult, TransportError> {
        if remote_candidates.is_empty() {
            return Err(TransportError::Configuration(
                "direct probing requires at least one remote candidate".to_owned(),
            ));
        }
        if timeout.is_zero() {
            return Err(TransportError::Configuration(
                "probe timeout must be greater than zero".to_owned(),
            ));
        }

        let local = self.socket.local_addr().map_err(TransportError::Network)?;
        let remotes = remote_candidates
            .iter()
            .copied()
            .filter(|remote| same_address_family(local, remote.ip()))
            .collect::<HashSet<_>>();
        if remotes.is_empty() {
            return Err(TransportError::Configuration(
                "remote candidates have no address family in common with the local socket"
                    .to_owned(),
            ));
        }

        let started = Instant::now();
        let deadline = started + timeout;
        let mut send_tick = interval_at(started, PROBE_PERIOD);
        send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut buffer = [0; 512];
        let mut outstanding = HashMap::<[u8; PROBE_NONCE_LEN], SocketAddr>::new();
        let mut seen_requests = HashSet::<[u8; PROBE_NONCE_LEN]>::new();
        let mut saw_peer_request = false;
        let mut received_ack_from = None;
        let mut confirmed_at = None;

        loop {
            let now = Instant::now();
            if saw_peer_request && let Some(peer_addr) = received_ack_from {
                let confirmed = *confirmed_at.get_or_insert(now);
                if now >= confirmed + PROBE_SETTLE {
                    return Ok(ProbeResult { peer_addr });
                }
            }
            if confirmed_at.is_none() && now >= deadline {
                return Err(TransportError::Timeout("UDP hole-punch probe"));
            }
            let stop_at = confirmed_at
                .map(|instant| instant + PROBE_SETTLE)
                .unwrap_or(deadline);

            tokio::select! {
                _ = send_tick.tick() => {
                    if Instant::now() >= stop_at {
                        continue;
                    }
                    for remote in &remotes {
                        let mut nonce = [0; PROBE_NONCE_LEN];
                        rand::rng().fill(&mut nonce);
                        let packet = encode_probe(&probe_token, session_id, PROBE_REQUEST, nonce);
                        self.socket.send_to(&packet, remote).await.map_err(TransportError::Network)?;
                        outstanding.insert(nonce, *remote);
                    }
                }
                received = self.socket.recv_from(&mut buffer) => {
                    let (length, source) = received.map_err(TransportError::Network)?;
                    let Some((kind, nonce)) = decode_probe(&buffer[..length], &probe_token, session_id)? else {
                        continue;
                    };
                    match kind {
                        PROBE_REQUEST => {
                            if seen_requests.insert(nonce) {
                                saw_peer_request = true;
                            }
                            let acknowledgement = encode_probe(&probe_token, session_id, PROBE_ACK, nonce);
                            self.socket.send_to(&acknowledgement, source).await.map_err(TransportError::Network)?;
                        }
                        PROBE_ACK => {
                            if outstanding.remove(&nonce).is_some() {
                                received_ack_from.get_or_insert(source);
                            }
                        }
                        _ => return Err(TransportError::ProtocolViolation("unknown UDP probe type".to_owned())),
                    }
                }
                _ = sleep_until(stop_at) => {
                    if let Some(peer_addr) = received_ack_from.filter(|_| saw_peer_request) {
                        return Ok(ProbeResult { peer_addr });
                    }
                    return Err(TransportError::Timeout("UDP hole-punch probe"));
                }
            }
        }
    }

    pub(crate) fn into_std_socket(self) -> io::Result<StdUdpSocket> {
        self.socket.into_std()
    }
}

fn local_candidates(local: SocketAddr) -> Result<Vec<SocketAddr>, TransportError> {
    let port = local.port();
    let mut candidates = Vec::new();
    if !local.ip().is_unspecified() {
        candidates.push(local);
    }
    let interfaces = if_addrs::get_if_addrs().map_err(TransportError::Network)?;
    for interface in interfaces {
        let ip = interface.ip();
        if !ip.is_unspecified() && same_address_family(local, ip) {
            candidates.push(SocketAddr::new(ip, port));
        }
    }
    Ok(candidates)
}

fn encode_probe(
    key: &[u8; 32],
    session_id: Uuid,
    kind: u8,
    nonce: [u8; PROBE_NONCE_LEN],
) -> [u8; PROBE_PACKET_LEN] {
    let mut packet = [0; PROBE_PACKET_LEN];
    packet[..4].copy_from_slice(PROBE_MAGIC);
    packet[4..20].copy_from_slice(session_id.as_bytes());
    packet[20] = kind;
    packet[21..PROBE_HEADER_LEN].copy_from_slice(&nonce);
    let mut mac = HmacSha256::new_from_slice(key).expect("32-byte HMAC key is valid");
    mac.update(&packet[..PROBE_HEADER_LEN]);
    packet[PROBE_HEADER_LEN..].copy_from_slice(&mac.finalize().into_bytes());
    packet
}

fn decode_probe(
    packet: &[u8],
    key: &[u8; 32],
    expected_session: Uuid,
) -> Result<Option<(u8, [u8; PROBE_NONCE_LEN])>, TransportError> {
    if packet.len() < PROBE_MAGIC.len() || &packet[..PROBE_MAGIC.len()] != PROBE_MAGIC {
        return Ok(None);
    }
    if packet.len() != PROBE_PACKET_LEN {
        return Err(TransportError::ProtocolViolation(
            "UDP probe packet has an invalid length".to_owned(),
        ));
    }
    if packet[4..20] != expected_session.as_bytes()[..] {
        return Ok(None);
    }
    let kind = packet[20];
    if !matches!(kind, PROBE_REQUEST | PROBE_ACK) {
        return Err(TransportError::ProtocolViolation(
            "UDP probe packet has an unknown type".to_owned(),
        ));
    }
    let mut mac = HmacSha256::new_from_slice(key).expect("32-byte HMAC key is valid");
    mac.update(&packet[..PROBE_HEADER_LEN]);
    mac.verify_slice(&packet[PROBE_HEADER_LEN..])
        .map_err(|_| TransportError::Authentication("UDP probe HMAC is invalid".to_owned()))?;
    let mut nonce = [0; PROBE_NONCE_LEN];
    nonce.copy_from_slice(&packet[21..PROBE_HEADER_LEN]);
    Ok(Some((kind, nonce)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_packet_authenticates_session_and_nonce() {
        let session = Uuid::new_v4();
        let token = [0x42; 32];
        let nonce = [0x17; PROBE_NONCE_LEN];
        let packet = encode_probe(&token, session, PROBE_ACK, nonce);
        assert_eq!(
            decode_probe(&packet, &token, session).unwrap(),
            Some((PROBE_ACK, nonce))
        );
        assert_eq!(decode_probe(&packet, &token, Uuid::new_v4()).unwrap(), None);

        let mut modified = packet;
        modified[PROBE_HEADER_LEN] ^= 1;
        assert!(matches!(
            decode_probe(&modified, &token, session),
            Err(TransportError::Authentication(_))
        ));
    }
}
