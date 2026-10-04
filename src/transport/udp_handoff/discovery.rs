//! QAD mapping discovery and validation for the measured mode-2 strategy.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
    time::Duration,
};

use iroh::RelayMode;
use tokio::{
    net::lookup_host,
    time::{Instant, timeout_at},
};

use super::super::{
    TransportError,
    iroh::build_ca_tls_config,
    qad::{QadObservation, QadReflector, observe_ipv4_mappings},
};
use super::{DiscoveredUdpSocket, MappingDiscovery, PunchError, PunchRole, QadPlan};
use crate::config::TlsConfig;

pub(super) const PRIVATE_QAD_PORT: u16 = 3478;
const MAPPING_DISCOVERY_BUDGET: Duration = Duration::from_secs(2);

/// Discover this node's IPv4 QAD mappings on the same wildcard-bound socket retained for punch.
///
/// QAD timeouts and route failures return `Unavailable`, so the caller can choose the standard
/// native Iroh path. Certificate, TLS, configuration, and protocol failures remain errors.
pub async fn discover_ipv4_mappings(
    qad_plan: &QadPlan,
    tls: &TlsConfig,
    deadline: Instant,
) -> Result<MappingDiscovery, TransportError> {
    crate::transport::ensure_rustls_provider();
    let cleanup_deadline = deadline;
    let probe_deadline = std::cmp::min(cleanup_deadline, Instant::now() + MAPPING_DISCOVERY_BUDGET);
    let socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(TransportError::Network)?;
    socket
        .set_nonblocking(true)
        .map_err(TransportError::Network)?;
    let local_socket = match socket.local_addr().map_err(TransportError::Network)? {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => {
            return Err(TransportError::Configuration(
                "QAD discovery requires an IPv4 socket".to_owned(),
            ));
        }
    };

    let reflectors = match qad_reflectors(qad_plan, probe_deadline).await {
        Ok(reflectors) => reflectors,
        Err(error) if error.is_network_failure() => {
            return Ok(MappingDiscovery::Unavailable {
                reason: error.to_string(),
            });
        }
        Err(error) => return Err(error),
    };
    let ca_tls = build_ca_tls_config(tls)?;
    let crypto_provider = rustls::crypto::CryptoProvider::get_default()
        .expect("ring crypto provider installed by ensure_rustls_provider")
        .clone();
    let tls = ca_tls
        .client_config(crypto_provider)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let probe_socket = socket.try_clone().map_err(TransportError::Network)?;
    let observations = match observe_ipv4_mappings(
        probe_socket,
        tls,
        &reflectors,
        probe_deadline,
        cleanup_deadline,
    )
    .await
    {
        Ok((probe_socket, observations)) => {
            drop(probe_socket);
            observations
        }
        Err(error) => return classify_qad_error(error),
    };
    if observations.len() != reflectors.len()
        || observations.iter().any(|observation| {
            observation.local_socket != local_socket
                || !observation.handshake_confirmed
                || observation.udp_tx_datagrams == 0
                || observation.udp_rx_datagrams == 0
                || observation.udp_tx_bytes == 0
                || observation.udp_rx_bytes == 0
        })
    {
        return Err(TransportError::ProtocolViolation(
            "QAD returned observations that do not match the retained UDP socket".to_owned(),
        ));
    }
    Ok(MappingDiscovery::Ready(DiscoveredUdpSocket {
        socket,
        local_socket,
        observations,
        qad_plan: qad_plan.clone(),
    }))
}

async fn qad_reflectors(
    qad_plan: &QadPlan,
    deadline: Instant,
) -> Result<Vec<QadReflector>, TransportError> {
    let mut configs = Vec::new();
    match qad_plan {
        QadPlan::PrivateAndOfficial {
            server_url,
            udp_port,
        } => {
            if *udp_port != PRIVATE_QAD_PORT {
                return Err(TransportError::Configuration(
                    "private server QAD port is fixed at UDP 3478".to_owned(),
                ));
            }
            let host = server_url.host_str().ok_or_else(|| {
                TransportError::Configuration("private relay URL has no host".to_owned())
            })?;
            configs.push((host.to_owned(), *udp_port));
            let official = default_qad_configs(1)?;
            configs.push(official[0].clone());
        }
        QadPlan::OfficialDefault => configs.extend(default_qad_configs(2)?),
    }

    let mut reflectors = Vec::with_capacity(configs.len());
    for (server_name, port) in configs {
        let addresses = timeout_at(deadline, lookup_host((server_name.as_str(), port)))
            .await
            .map_err(|_| TransportError::Timeout("resolving QAD reflector"))?
            .map_err(TransportError::Network)?;
        let addr = addresses
            .filter_map(|address| match address {
                SocketAddr::V4(address) => Some(address),
                SocketAddr::V6(_) => None,
            })
            .next()
            .ok_or_else(|| {
                TransportError::Network(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("QAD reflector {server_name} has no IPv4 address"),
                ))
            })?;
        reflectors.push(QadReflector { addr, server_name });
    }
    Ok(reflectors)
}

pub(super) fn default_qad_configs(count: usize) -> Result<Vec<(String, u16)>, TransportError> {
    let configs = RelayMode::Default
        .relay_map()
        .relays::<Vec<_>>()
        .into_iter()
        .filter_map(|relay| {
            let host = relay.url.host_str()?.to_owned();
            let port = relay.quic.as_ref()?.port;
            Some((host, port))
        })
        .take(count)
        .collect::<Vec<_>>();
    if configs.len() != count {
        return Err(TransportError::Configuration(format!(
            "SDK default relay map exposes {} QAD reflectors; {count} required",
            configs.len()
        )));
    }
    Ok(configs)
}

fn classify_qad_error(error: anyhow::Error) -> Result<MappingDiscovery, TransportError> {
    let reason = format!("{error:#}");
    let causes = error.chain().collect::<Vec<_>>();
    if causes.iter().any(|cause| {
        cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    }) {
        return Ok(MappingDiscovery::Unavailable { reason });
    }
    if causes
        .iter()
        .any(|cause| crate::transport::is_auth_failure_source(*cause))
    {
        return Err(TransportError::Authentication(reason));
    }
    if causes
        .iter()
        .any(|cause| crate::transport::is_network_failure_source(*cause))
    {
        return Ok(MappingDiscovery::Unavailable { reason });
    }
    Err(TransportError::Iroh(reason))
}

#[derive(Clone, Copy, Debug)]
struct MappingPair {
    first: SocketAddrV4,
    second: SocketAddrV4,
}

pub(super) fn validate_mapping_pair(
    role: PunchRole,
    qad_plan: &QadPlan,
    local_socket: SocketAddrV4,
    local_observations: &[QadObservation],
    peer_local_socket: SocketAddrV4,
    peer_observations: &[QadObservation],
) -> Result<(), PunchError> {
    validate_observations(qad_plan, local_observations, local_socket)?;
    validate_observations(qad_plan, peer_observations, peer_local_socket)?;
    let (target, client) = match role {
        PunchRole::Target => (local_observations, peer_observations),
        PunchRole::Client => (peer_observations, local_observations),
    };
    let target_pair = mapping_pair(target)?;
    let client_pair = mapping_pair(client)?;
    if target_pair.first.ip() != target_pair.second.ip()
        || target_pair.first.port().abs_diff(target_pair.second.port()) <= 5
    {
        return Err(PunchError::Unavailable(
            "target QAD mappings do not meet the measured mode-2 precondition".to_owned(),
        ));
    }
    if client_pair.first != client_pair.second {
        return Err(PunchError::Unavailable(
            "client QAD mappings are not stable across the configured reflectors".to_owned(),
        ));
    }
    Ok(())
}

fn validate_observations(
    qad_plan: &QadPlan,
    observations: &[QadObservation],
    expected_local_socket: SocketAddrV4,
) -> Result<(), PunchError> {
    if observations.len() != 2 {
        return Err(PunchError::Unavailable(
            "mode 2 requires exactly two authenticated QAD observations per endpoint".to_owned(),
        ));
    }
    let expected = expected_reflector_servers(qad_plan)?;
    let mut unmatched = observations.iter().collect::<Vec<_>>();
    for (server_name, port) in expected {
        let Some(index) = unmatched.iter().position(|observation| {
            observation.reflector.server_name == server_name
                && observation.reflector.addr.port() == port
        }) else {
            return Err(PunchError::Unavailable(
                "QAD observations do not match the configured private or official reflectors"
                    .to_owned(),
            ));
        };
        unmatched.remove(index);
    }
    if !unmatched.is_empty() {
        return Err(PunchError::Unavailable(
            "QAD observations include a reflector outside the selected relay mode".to_owned(),
        ));
    }
    for observation in observations {
        if observation.local_socket != expected_local_socket
            || !observation.handshake_confirmed
            || observation.udp_tx_datagrams == 0
            || observation.udp_rx_datagrams == 0
            || observation.udp_tx_bytes == 0
            || observation.udp_rx_bytes == 0
        {
            return Err(PunchError::Unavailable(
                "QAD observation does not match its socket or lacks bidirectional UDP evidence"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn mapping_pair(observations: &[QadObservation]) -> Result<MappingPair, PunchError> {
    let first = observations
        .first()
        .map(|observation| observation.observed_addr)
        .ok_or_else(|| {
            TransportError::ProtocolViolation("first QAD mapping is missing".to_owned())
        })?;
    let second = observations
        .get(1)
        .map(|observation| observation.observed_addr)
        .ok_or_else(|| {
            TransportError::ProtocolViolation("second QAD mapping is missing".to_owned())
        })?;
    Ok(MappingPair { first, second })
}

pub(super) fn target_public_ip(observations: &[QadObservation]) -> Result<Ipv4Addr, PunchError> {
    let pair = mapping_pair(observations)?;
    if pair.first.ip() != pair.second.ip() {
        return Err(PunchError::Unavailable(
            "target QAD mappings use different public IPv4 addresses".to_owned(),
        ));
    }
    Ok(*pair.first.ip())
}

fn expected_reflector_servers(qad_plan: &QadPlan) -> Result<Vec<(String, u16)>, PunchError> {
    let mut reflectors = Vec::new();
    match qad_plan {
        QadPlan::PrivateAndOfficial {
            server_url,
            udp_port,
        } => {
            if *udp_port != PRIVATE_QAD_PORT {
                return Err(TransportError::Configuration(
                    "private server QAD port is fixed at UDP 3478".to_owned(),
                )
                .into());
            }
            let server_name = server_url.host_str().ok_or_else(|| {
                TransportError::Configuration("private relay URL has no host".to_owned())
            })?;
            reflectors.push((server_name.to_owned(), PRIVATE_QAD_PORT));
            reflectors.extend(default_qad_configs(1)?);
        }
        QadPlan::OfficialDefault => reflectors.extend(default_qad_configs(2)?),
    }
    Ok(reflectors)
}

pub(super) fn unique_observed_addrs(
    observations: &[QadObservation],
) -> Result<Vec<SocketAddrV4>, PunchError> {
    let mut addresses = Vec::with_capacity(observations.len());
    for observation in observations {
        let SocketAddr::V4(address) = observation.observed_addr.into() else {
            return Err(
                TransportError::ProtocolViolation("QAD candidate is not IPv4".to_owned()).into(),
            );
        };
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}
