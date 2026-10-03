//! Authenticated IPv4 UDP hole punching before handing a selected tuple to Iroh.

use std::{
    collections::HashSet,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use iroh::{EndpointId, RelayMode, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::{UdpSocket, lookup_host},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, interval, sleep_until, timeout_at},
};
use uuid::Uuid;

use super::{
    TransportError,
    iroh::{RelayChoice, build_ca_tls_config, validate_relay_url},
    qad::{QadObservation, QadReflector, observe_ipv4_mappings},
};
use crate::config::TlsConfig;

const PRIVATE_QAD_PORT: u16 = 3478;
const OFFICIAL_QAD_PORT: u16 = 7842;
const TARGET_SOCKET_COUNT: usize = 257;
const CLIENT_RANDOM_PORT_PROBES: usize = 1000;
const PROBE_CADENCE: Duration = Duration::from_millis(15);
const SELECT_CADENCE: Duration = Duration::from_millis(150);
const TARGET_PROBE_BUDGET: Duration = Duration::from_secs(38);
const CLIENT_PROBE_BUDGET: Duration = Duration::from_secs(35);
const MAPPING_DISCOVERY_BUDGET: Duration = Duration::from_secs(2);
const SELECT_NONE: Option<u16> = None;
const PACKET_MAGIC: &[u8; 8] = b"KMSHPN01";
const PACKET_HEADER_LEN: usize = 92;
const PACKET_SIGNATURE_LEN: usize = 64;
const PACKET_LEN: usize = PACKET_HEADER_LEN + PACKET_SIGNATURE_LEN;
const PROBE_INDEX: u16 = u16::MAX;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PunchRole {
    Target,
    Client,
}

impl PunchRole {
    fn wire(self) -> u8 {
        match self {
            Self::Target => 0,
            Self::Client => 1,
        }
    }
}

struct Packet {
    kind: PacketKind,
    index: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PacketKind {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PunchIdentity {
    pub session_id: Uuid,
    pub target_id: EndpointId,
    pub client_id: EndpointId,
}

#[derive(Debug)]
pub struct DiscoveredUdpSocket {
    pub socket: StdUdpSocket,
    pub local_socket: SocketAddrV4,
    pub observations: Vec<QadObservation>,
    pub relay_choice: RelayChoice,
}

#[derive(Debug)]
pub enum MappingDiscovery {
    Ready(DiscoveredUdpSocket),
    Unavailable { reason: String },
}

#[derive(Debug, Error)]
pub enum PunchError {
    #[error("direct UDP path unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Fatal(#[from] TransportError),
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PunchCounters {
    pub tx_datagrams: u64,
    pub tx_bytes: u64,
    pub rx_datagrams: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PunchSelection {
    pub index: u16,
    pub local_socket: SocketAddrV4,
    pub peer_observed_addr: SocketAddrV4,
    pub counters: PunchCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalBindState {
    pub index: u16,
    pub bind_addr: SocketAddrV4,
}

#[derive(Clone, Copy, Debug)]
struct MappingPair {
    first: SocketAddrV4,
    second: SocketAddrV4,
}

/// Discover this node's IPv4 QAD mappings on the same wildcard-bound socket retained for punch.
///
/// QAD timeouts and route failures return `Unavailable`, so the caller can choose the standard
/// native Iroh path. Certificate, TLS, configuration, and protocol failures remain errors.
pub async fn discover_ipv4_mappings(
    relay_choice: &RelayChoice,
    tls: &TlsConfig,
    deadline: Instant,
) -> Result<MappingDiscovery, TransportError> {
    super::ensure_rustls_provider();
    let deadline = std::cmp::min(deadline, Instant::now() + MAPPING_DISCOVERY_BUDGET);
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

    let reflectors = match qad_reflectors(relay_choice, deadline).await {
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
    let observed = timeout_at(
        deadline,
        observe_ipv4_mappings(probe_socket, tls, &reflectors, deadline),
    )
    .await;
    let observations = match observed {
        Err(_) => {
            return Ok(MappingDiscovery::Unavailable {
                reason: "QAD mapping discovery deadline elapsed".to_owned(),
            });
        }
        Ok(Ok((probe_socket, observations))) => {
            drop(probe_socket);
            observations
        }
        Ok(Err(error)) => return classify_qad_error(error),
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
        relay_choice: relay_choice.clone(),
    }))
}

async fn qad_reflectors(
    relay_choice: &RelayChoice,
    deadline: Instant,
) -> Result<Vec<QadReflector>, TransportError> {
    let mut configs = Vec::new();
    match relay_choice {
        RelayChoice::Private { url, qad_port } => {
            if *qad_port != PRIVATE_QAD_PORT {
                return Err(TransportError::Configuration(
                    "private server QAD port is fixed at UDP 3478".to_owned(),
                ));
            }
            let url = validate_relay_url(url.clone())?;
            let host = url.host_str().ok_or_else(|| {
                TransportError::Configuration("private relay URL has no host".to_owned())
            })?;
            configs.push((host.to_owned(), *qad_port));
            let official = default_qad_configs(1)?;
            configs.push(official[0].clone());
        }
        RelayChoice::PublicDefault => configs.extend(default_qad_configs(2)?),
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

fn default_qad_configs(count: usize) -> Result<Vec<(String, u16)>, TransportError> {
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
        .any(|cause| super::is_auth_failure_source(*cause))
    {
        return Err(TransportError::Authentication(reason));
    }
    if causes
        .iter()
        .any(|cause| super::is_network_failure_source(*cause))
    {
        return Ok(MappingDiscovery::Unavailable { reason });
    }
    Err(TransportError::Iroh(reason))
}

#[derive(Default)]
struct Counters {
    tx_datagrams: AtomicU64,
    tx_bytes: AtomicU64,
    rx_datagrams: AtomicU64,
    rx_bytes: AtomicU64,
}

impl Counters {
    fn sent(&self, bytes: usize) {
        self.tx_datagrams.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn received(&self, bytes: usize) {
        self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PunchCounters {
        PunchCounters {
            tx_datagrams: self.tx_datagrams.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
        }
    }
}

struct PunchSocket {
    index: u16,
    local_socket: SocketAddrV4,
    socket: Arc<UdpSocket>,
    counters: Arc<Counters>,
}

enum TargetEvent {
    Selected(PunchSelection),
}

/// Owns every raw socket and receive task for one SSH connection's P2P attempt.
pub struct PreparedPunch {
    role: PunchRole,
    identity: PunchIdentity,
    secret_key: SecretKey,
    peer_id: EndpointId,
    peer_observations: Vec<QadObservation>,
    target_ip: Ipv4Addr,
    sockets: Vec<PunchSocket>,
    workers: JoinSet<Result<(), PunchError>>,
    selected: Option<PunchSelection>,
    started: bool,
    cancelled: bool,
}

impl PreparedPunch {
    /// Bind all sockets for this attempt without sending punch packets.
    pub fn prepare(
        role: PunchRole,
        identity: PunchIdentity,
        secret_key: SecretKey,
        discovered: DiscoveredUdpSocket,
        peer_local_socket: SocketAddrV4,
        peer_observations: Vec<QadObservation>,
    ) -> Result<Self, PunchError> {
        if identity.target_id == identity.client_id {
            return Err(TransportError::ProtocolViolation(
                "target and client EndpointIds must be distinct".to_owned(),
            )
            .into());
        }
        let local_id = match role {
            PunchRole::Target => identity.target_id,
            PunchRole::Client => identity.client_id,
        };
        if secret_key.public() != local_id {
            return Err(TransportError::ProtocolViolation(
                "registered endpoint key does not match the punch role identity".to_owned(),
            )
            .into());
        }
        validate_mapping_pair(
            role,
            &discovered.relay_choice,
            discovered.local_socket,
            &discovered.observations,
            peer_local_socket,
            &peer_observations,
        )?;
        let target_observations = if role == PunchRole::Target {
            &discovered.observations
        } else {
            &peer_observations
        };
        let target_ip = target_public_ip(target_observations)?;
        discovered
            .socket
            .set_nonblocking(true)
            .map_err(TransportError::Network)?;
        let original = UdpSocket::from_std(discovered.socket).map_err(TransportError::Network)?;
        let mut sockets = Vec::with_capacity(if role == PunchRole::Target {
            TARGET_SOCKET_COUNT
        } else {
            1
        });
        sockets.push(PunchSocket {
            index: 0,
            local_socket: discovered.local_socket,
            socket: Arc::new(original),
            counters: Arc::new(Counters::default()),
        });
        if role == PunchRole::Target {
            for index in 1..TARGET_SOCKET_COUNT {
                let std_socket =
                    StdUdpSocket::bind(SocketAddrV4::new(*discovered.local_socket.ip(), 0))
                        .map_err(|error| PunchError::Unavailable(error.to_string()))?;
                std_socket
                    .set_nonblocking(true)
                    .map_err(TransportError::Network)?;
                let local_socket = match std_socket.local_addr().map_err(TransportError::Network)? {
                    SocketAddr::V4(address) => address,
                    SocketAddr::V6(_) => {
                        return Err(TransportError::Configuration(
                            "target punch socket unexpectedly bound IPv6".to_owned(),
                        )
                        .into());
                    }
                };
                let socket = UdpSocket::from_std(std_socket).map_err(TransportError::Network)?;
                sockets.push(PunchSocket {
                    index: index as u16,
                    local_socket,
                    socket: Arc::new(socket),
                    counters: Arc::new(Counters::default()),
                });
            }
        }
        Ok(Self {
            role,
            identity,
            secret_key,
            peer_id: role_peer_id(role, identity),
            peer_observations,
            target_ip,
            sockets,
            workers: JoinSet::new(),
            selected: None,
            started: false,
            cancelled: false,
        })
    }

    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// Start this role's bounded scan after the control plane's StartPunch message.
    pub async fn start(&mut self, deadline: Instant) -> Result<PunchSelection, PunchError> {
        if self.started || self.cancelled {
            return Err(TransportError::ProtocolViolation(
                "punch session can be started once before cancellation".to_owned(),
            )
            .into());
        }
        self.started = true;
        let result = match self.role {
            PunchRole::Target => self.start_target(deadline).await,
            PunchRole::Client => self.start_client(deadline).await,
        };
        match result {
            Ok(selection) => {
                self.selected = Some(selection);
                Ok(selection)
            }
            Err(error) => {
                let cleanup = self.cancel().await;
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(PunchError::Fatal(cleanup_error)),
                }
            }
        }
    }

    /// Stop all receive workers, await their termination, and release every raw socket.
    pub async fn cancel(&mut self) -> Result<(), TransportError> {
        if self.cancelled {
            return Ok(());
        }
        self.cancelled = true;
        self.workers.abort_all();
        let mut failure = None;
        while let Some(result) = self.workers.join_next().await {
            match result {
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    failure.get_or_insert_with(|| TransportError::Iroh(error.to_string()));
                }
                Ok(Err(PunchError::Fatal(error))) => {
                    failure.get_or_insert(error);
                }
                Ok(Err(PunchError::Unavailable(_))) => {}
                Ok(Ok(())) => {}
            }
        }
        self.sockets.clear();
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Close all raw sockets before the caller binds Iroh to the selected tuple.
    pub async fn finish(
        mut self,
        selected: bool,
    ) -> Result<Option<LocalBindState>, TransportError> {
        let bind_state = if selected {
            self.selected.map(|selection| LocalBindState {
                index: selection.index,
                bind_addr: selection.local_socket,
            })
        } else {
            None
        };
        let cleanup = self.cancel().await;
        if selected && bind_state.is_none() {
            return Err(TransportError::ProtocolViolation(
                "selected punch session has no authenticated socket selection".to_owned(),
            ));
        }
        cleanup?;
        Ok(bind_state)
    }

    async fn start_target(&mut self, deadline: Instant) -> Result<PunchSelection, PunchError> {
        let (event_sender, mut events) = mpsc::channel(1);
        let (selected_sender, selected_receiver) = watch::channel(SELECT_NONE);
        let selection = Arc::new(Mutex::new(None));
        for local in &self.sockets {
            let event_sender = event_sender.clone();
            let selected_sender = selected_sender.clone();
            let selected_receiver = selected_receiver.clone();
            let selection = selection.clone();
            let socket = local.socket.clone();
            let counters = local.counters.clone();
            let secret_key = self.secret_key.clone();
            let identity = self.identity;
            let peer_id = self.peer_id;
            let index = local.index;
            let local_socket = local.local_socket;
            self.workers.spawn(async move {
                target_receiver(
                    index,
                    local_socket,
                    socket,
                    counters,
                    event_sender,
                    selected_sender,
                    selected_receiver,
                    selection,
                    secret_key,
                    identity,
                    peer_id,
                )
                .await
            });
        }
        drop(event_sender);

        let peer_addrs = unique_observed_addrs(&self.peer_observations)?;
        for local in &self.sockets {
            for peer_addr in &peer_addrs {
                send_packet(
                    &local.socket,
                    &local.counters,
                    &self.secret_key,
                    self.identity,
                    PunchRole::Target,
                    PacketKind::Offer,
                    local.index,
                    SocketAddr::V4(*peer_addr),
                )
                .await?;
            }
        }

        let raw_deadline = std::cmp::min(Instant::now() + TARGET_PROBE_BUDGET, deadline);
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Some(TargetEvent::Selected(selection)) => return Ok(selection),
                    None => return Err(PunchError::Fatal(TransportError::Iroh(
                        "target punch workers ended before selecting a socket".to_owned()
                    ))),
                },
                result = self.workers.join_next() => match result {
                    Some(Ok(Ok(()))) if selection.lock().expect("punch selection mutex poisoned").is_none() => {
                        return Err(PunchError::Unavailable(
                            "target punch receiver stopped before selection".to_owned()
                        ));
                    }
                    Some(Ok(Ok(()))) => {},
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => return Err(PunchError::Fatal(TransportError::Iroh(
                        format!("target punch receiver task failed: {error}")
                    ))),
                    None => return Err(PunchError::Unavailable(
                        "target punch has no active receiver".to_owned()
                    )),
                },
                _ = sleep_until(raw_deadline) => return Err(PunchError::Unavailable(
                    "target did not receive a signed Select before the punch deadline".to_owned()
                )),
            }
        }
    }

    async fn start_client(&mut self, deadline: Instant) -> Result<PunchSelection, PunchError> {
        let local = self.sockets.first().expect("client owns its QAD socket");
        let socket = &local.socket;
        let counters = &local.counters;
        let known_addrs = unique_observed_addrs(&self.peer_observations)?;
        let mut tried_ports = known_addrs
            .iter()
            .filter(|address| *address.ip() == self.target_ip)
            .map(SocketAddrV4::port)
            .collect::<HashSet<_>>();
        for address in &known_addrs {
            send_packet(
                socket,
                counters,
                &self.secret_key,
                self.identity,
                PunchRole::Client,
                PacketKind::Probe,
                PROBE_INDEX,
                SocketAddr::V4(*address),
            )
            .await?;
        }

        let raw_deadline = std::cmp::min(Instant::now() + CLIENT_PROBE_BUDGET, deadline);
        let mut scan_tick = interval(PROBE_CADENCE);
        scan_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut select_tick = interval(SELECT_CADENCE);
        select_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut random_probes_sent = 0usize;
        let mut selected: Option<(u16, SocketAddrV4)> = None;
        let mut confirmed = false;
        let mut buffer = [0u8; 2048];

        loop {
            tokio::select! {
                received = socket.recv_from(&mut buffer) => {
                    let (len, source) = received.map_err(|error| io_punch_error(error))?;
                    counters.received(len);
                    let Some(source) = ipv4_source(source) else { continue };
                    let Some(packet) = decode_packet(
                        &buffer[..len], self.identity, self.peer_id, PunchRole::Target
                    ) else { continue };
                    match packet.kind {
                        PacketKind::Offer if usize::from(packet.index) < TARGET_SOCKET_COUNT => {
                            if selected.is_none() {
                                selected = Some((packet.index, source));
                                send_packet(
                                    socket, counters, &self.secret_key, self.identity,
                                    PunchRole::Client, PacketKind::Select, packet.index,
                                    SocketAddr::V4(source)
                                ).await?;
                            }
                        }
                        PacketKind::Confirm if selected == Some((packet.index, source)) => {
                            confirmed = true;
                        }
                        _ => {}
                    }
                }
                _ = scan_tick.tick(), if random_probes_sent < CLIENT_RANDOM_PORT_PROBES => {
                    let port = loop {
                        let candidate = rand::random_range(1024u16..65535u16);
                        if tried_ports.insert(candidate) {
                            break candidate;
                        }
                    };
                    send_packet(
                        socket, counters, &self.secret_key, self.identity,
                        PunchRole::Client, PacketKind::Probe, PROBE_INDEX,
                        SocketAddr::V4(SocketAddrV4::new(self.target_ip, port))
                    ).await?;
                    random_probes_sent += 1;
                }
                _ = select_tick.tick(), if selected.is_some() && !confirmed => {
                    let (index, address) = selected.expect("selection guard checked");
                    send_packet(
                        socket, counters, &self.secret_key, self.identity,
                        PunchRole::Client, PacketKind::Select, index,
                        SocketAddr::V4(address)
                    ).await?;
                }
                _ = sleep_until(raw_deadline) => {
                    return Err(PunchError::Unavailable(
                        "client did not receive a signed Offer and matching Confirm before the punch deadline".to_owned()
                    ));
                }
            }
            if confirmed {
                let (index, peer_observed_addr) = selected.expect("confirmed selection exists");
                return Ok(PunchSelection {
                    index,
                    local_socket: local.local_socket,
                    peer_observed_addr,
                    counters: counters.snapshot(),
                });
            }
        }
    }
}

async fn target_receiver(
    index: u16,
    local_socket: SocketAddrV4,
    socket: Arc<UdpSocket>,
    counters: Arc<Counters>,
    events: mpsc::Sender<TargetEvent>,
    selected_sender: watch::Sender<Option<u16>>,
    mut selected_receiver: watch::Receiver<Option<u16>>,
    selection: Arc<Mutex<Option<(u16, SocketAddrV4)>>>,
    secret_key: SecretKey,
    identity: PunchIdentity,
    peer_id: EndpointId,
) -> Result<(), PunchError> {
    let mut buffer = [0u8; 2048];
    loop {
        if selected_receiver
            .borrow()
            .is_some_and(|selected| selected != index)
        {
            return Ok(());
        }
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (len, source) = received.map_err(io_punch_error)?;
                counters.received(len);
                let Some(source) = ipv4_source(source) else { continue };
                let Some(packet) = decode_packet(
                    &buffer[..len], identity, peer_id, PunchRole::Client
                ) else { continue };
                match packet.kind {
                    PacketKind::Probe if packet.index == PROBE_INDEX => {
                        send_packet(
                            &socket, &counters, &secret_key, identity, PunchRole::Target,
                            PacketKind::Offer, index, SocketAddr::V4(source)
                        ).await?;
                    }
                    PacketKind::Select if packet.index == index => {
                        let source_selection = {
                            let mut current = selection.lock().expect("punch selection mutex poisoned");
                            match *current {
                                None => {
                                    *current = Some((index, source));
                                    let _ = selected_sender.send_replace(Some(index));
                                    Some(true)
                                }
                                Some((selected, selected_source)) if selected == index && selected_source == source => Some(false),
                                _ => None,
                            }
                        };
                        if source_selection.is_none() {
                            continue;
                        }
                        send_packet(
                            &socket, &counters, &secret_key, identity, PunchRole::Target,
                            PacketKind::Confirm, index, SocketAddr::V4(source)
                        ).await?;
                        if source_selection == Some(true) {
                            events.send(TargetEvent::Selected(PunchSelection {
                                index,
                                local_socket,
                                peer_observed_addr: source,
                                counters: counters.snapshot(),
                            })).await.map_err(|_| PunchError::Fatal(TransportError::Iroh(
                                "target selection coordinator stopped".to_owned()
                            )))?;
                        }
                    }
                    _ => {}
                }
            }
            changed = selected_receiver.changed() => {
                let selected = *selected_receiver.borrow_and_update();
                if changed.is_err() || selected.is_some_and(|selected| selected != index) {
                    return Ok(());
                }
            }
        }
    }
}

fn validate_mapping_pair(
    role: PunchRole,
    relay_choice: &RelayChoice,
    local_socket: SocketAddrV4,
    local_observations: &[QadObservation],
    peer_local_socket: SocketAddrV4,
    peer_observations: &[QadObservation],
) -> Result<(), PunchError> {
    validate_observations(relay_choice, local_observations, local_socket)?;
    validate_observations(relay_choice, peer_observations, peer_local_socket)?;
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
    relay_choice: &RelayChoice,
    observations: &[QadObservation],
    expected_local_socket: SocketAddrV4,
) -> Result<(), PunchError> {
    if observations.len() != 2 {
        return Err(PunchError::Unavailable(
            "mode 2 requires exactly two authenticated QAD observations per endpoint".to_owned(),
        ));
    }
    let expected = expected_reflector_servers(relay_choice)?;
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

fn target_public_ip(observations: &[QadObservation]) -> Result<Ipv4Addr, PunchError> {
    let pair = mapping_pair(observations)?;
    if pair.first.ip() != pair.second.ip() {
        return Err(PunchError::Unavailable(
            "target QAD mappings use different public IPv4 addresses".to_owned(),
        ));
    }
    Ok(*pair.first.ip())
}

fn expected_reflector_servers(
    relay_choice: &RelayChoice,
) -> Result<Vec<(String, u16)>, PunchError> {
    let mut reflectors = Vec::new();
    match relay_choice {
        RelayChoice::Private { url, qad_port } => {
            if *qad_port != PRIVATE_QAD_PORT {
                return Err(TransportError::Configuration(
                    "private server QAD port is fixed at UDP 3478".to_owned(),
                )
                .into());
            }
            let url = validate_relay_url(url.clone())?;
            let server_name = url.host_str().ok_or_else(|| {
                TransportError::Configuration("private relay URL has no host".to_owned())
            })?;
            reflectors.push((server_name.to_owned(), PRIVATE_QAD_PORT));
            reflectors.extend(default_qad_configs(1)?);
        }
        RelayChoice::PublicDefault => reflectors.extend(default_qad_configs(2)?),
    }
    Ok(reflectors)
}

fn unique_observed_addrs(observations: &[QadObservation]) -> Result<Vec<SocketAddrV4>, PunchError> {
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

fn role_peer_id(role: PunchRole, identity: PunchIdentity) -> EndpointId {
    match role {
        PunchRole::Target => identity.client_id,
        PunchRole::Client => identity.target_id,
    }
}

fn ipv4_source(address: SocketAddr) -> Option<SocketAddrV4> {
    match address {
        SocketAddr::V4(address) => Some(address),
        SocketAddr::V6(_) => None,
    }
}

fn io_punch_error(error: io::Error) -> PunchError {
    let transport = TransportError::Network(error);
    if transport.is_network_failure() {
        PunchError::Unavailable(transport.to_string())
    } else {
        PunchError::Fatal(transport)
    }
}

async fn send_packet(
    socket: &UdpSocket,
    counters: &Counters,
    secret_key: &SecretKey,
    identity: PunchIdentity,
    role: PunchRole,
    kind: PacketKind,
    index: u16,
    destination: SocketAddr,
) -> Result<(), PunchError> {
    let packet = encode_packet(secret_key, identity, role, kind, index);
    let sent = socket
        .send_to(&packet, destination)
        .await
        .map_err(io_punch_error)?;
    if sent != PACKET_LEN {
        return Err(PunchError::Fatal(TransportError::Iroh(format!(
            "UDP sent {sent} bytes for a {PACKET_LEN}-byte signed punch packet"
        ))));
    }
    counters.sent(sent);
    Ok(())
}

fn encode_packet(
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

fn decode_packet(
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

    fn private_choice() -> RelayChoice {
        RelayChoice::Private {
            url: "https://192.0.2.11:9443".parse().unwrap(),
            qad_port: PRIVATE_QAD_PORT,
        }
    }

    fn observations(
        local_socket: SocketAddrV4,
        first_observed: SocketAddrV4,
        second_observed: SocketAddrV4,
    ) -> Vec<QadObservation> {
        let official = default_qad_configs(1).unwrap().remove(0);
        vec![
            QadObservation {
                reflector: QadReflector {
                    addr: B_QAD_ADDR_FOR_TEST,
                    server_name: "192.0.2.11".to_owned(),
                },
                local_socket,
                observed_addr: first_observed,
                handshake_confirmed: true,
                udp_tx_datagrams: 3,
                udp_rx_datagrams: 3,
                udp_tx_bytes: 2400,
                udp_rx_bytes: 2400,
            },
            QadObservation {
                reflector: QadReflector {
                    addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), official.1),
                    server_name: official.0,
                },
                local_socket,
                observed_addr: second_observed,
                handshake_confirmed: true,
                udp_tx_datagrams: 3,
                udp_rx_datagrams: 3,
                udp_tx_bytes: 2400,
                udp_rx_bytes: 2400,
            },
        ]
    }

    const B_QAD_ADDR_FOR_TEST: SocketAddrV4 =
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 11), PRIVATE_QAD_PORT);

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

    #[tokio::test]
    async fn selected_target_index_matches_client_offer_and_releases_tuple() {
        let target_key = SecretKey::generate();
        let client_key = SecretKey::generate();
        let identity = PunchIdentity {
            session_id: Uuid::new_v4(),
            target_id: target_key.public(),
            client_id: client_key.public(),
        };
        let target_socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target_local = match target_socket.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        };
        let target_second_port = if target_local.port() <= u16::MAX - 10 {
            target_local.port() + 10
        } else {
            target_local.port() - 10
        };
        let target_observations = observations(
            target_local,
            target_local,
            SocketAddrV4::new(*target_local.ip(), target_second_port),
        );

        let client_socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_local = match client_socket.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        };
        let client_observations = observations(client_local, client_local, client_local);
        let relay_choice = private_choice();
        let mut target = PreparedPunch::prepare(
            PunchRole::Target,
            identity,
            target_key,
            DiscoveredUdpSocket {
                socket: target_socket,
                local_socket: target_local,
                observations: target_observations.clone(),
                relay_choice: relay_choice.clone(),
            },
            client_local,
            client_observations.clone(),
        )
        .unwrap();
        let mut client = PreparedPunch::prepare(
            PunchRole::Client,
            identity,
            client_key,
            DiscoveredUdpSocket {
                socket: client_socket,
                local_socket: client_local,
                observations: client_observations,
                relay_choice,
            },
            target_local,
            target_observations,
        )
        .unwrap();
        assert_eq!(target.socket_count(), TARGET_SOCKET_COUNT);
        assert_eq!(client.socket_count(), 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        let (target_selection, client_selection) =
            tokio::join!(target.start(deadline), client.start(deadline));
        let target_selection = target_selection.unwrap();
        let client_selection = client_selection.unwrap();
        assert_eq!(target_selection.index, client_selection.index);
        assert_eq!(
            target.sockets[usize::from(target_selection.index)].local_socket,
            target_selection.local_socket
        );
        assert_eq!(
            target_selection.peer_observed_addr,
            client_selection.local_socket
        );
        assert_eq!(
            client_selection.peer_observed_addr,
            target_selection.local_socket
        );

        let target_bind = target.finish(true).await.unwrap().unwrap();
        let client_bind = client.finish(true).await.unwrap().unwrap();
        assert_eq!(target_bind.index, target_selection.index);
        assert_eq!(target_bind.bind_addr, target_selection.local_socket);
        assert_eq!(client_bind.bind_addr, client_selection.local_socket);
        StdUdpSocket::bind(target_bind.bind_addr).unwrap();
        StdUdpSocket::bind(client_bind.bind_addr).unwrap();
    }

    #[tokio::test]
    async fn unavailable_start_keeps_network_classification_and_releases_socket() {
        let target_key = SecretKey::generate();
        let client_key = SecretKey::generate();
        let identity = PunchIdentity {
            session_id: Uuid::new_v4(),
            target_id: target_key.public(),
            client_id: client_key.public(),
        };
        let target_socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target_local = match target_socket.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        };
        let target_second_port = if target_local.port() <= u16::MAX - 10 {
            target_local.port() + 10
        } else {
            target_local.port() - 10
        };
        let target_observations = observations(
            target_local,
            target_local,
            SocketAddrV4::new(*target_local.ip(), target_second_port),
        );
        drop(target_socket);

        let client_socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_local = match client_socket.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        };
        let client_observations = observations(client_local, client_local, client_local);
        let mut prepared = PreparedPunch::prepare(
            PunchRole::Client,
            identity,
            client_key,
            DiscoveredUdpSocket {
                socket: client_socket,
                local_socket: client_local,
                observations: client_observations,
                relay_choice: private_choice(),
            },
            target_local,
            target_observations,
        )
        .unwrap();

        let result = prepared
            .start(Instant::now() - Duration::from_millis(1))
            .await;
        assert!(matches!(result, Err(PunchError::Unavailable(_))));
        assert_eq!(prepared.socket_count(), 0);
        StdUdpSocket::bind(client_local).unwrap();
    }
}
