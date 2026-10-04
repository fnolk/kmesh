//! Per-session bounded UDP probing and selected-socket lifecycle.

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

use iroh::{EndpointId, SecretKey};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, interval, sleep_until},
};

use super::super::TransportError;
use super::super::qad::QadObservation;
use super::discovery::{target_public_ip, unique_observed_addrs, validate_mapping_pair};
use super::packet::{PACKET_LEN, PacketKind, decode_packet, encode_packet};
use super::{
    DiscoveredUdpSocket, LocalBindState, PunchCounters, PunchError, PunchIdentity, PunchRole,
    PunchSelection,
};

const TARGET_SOCKET_COUNT: usize = 257;
const CLIENT_RANDOM_PORT_PROBES: usize = 1000;
const PROBE_CADENCE: Duration = Duration::from_millis(15);
const SELECT_CADENCE: Duration = Duration::from_millis(150);
const TARGET_PROBE_BUDGET: Duration = Duration::from_secs(38);
const CLIENT_PROBE_BUDGET: Duration = Duration::from_secs(35);
const SELECT_NONE: Option<u16> = None;
const PROBE_INDEX: u16 = u16::MAX;

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

#[derive(Clone)]
struct PunchSocket {
    index: u16,
    local_socket: SocketAddrV4,
    socket: Arc<UdpSocket>,
    counters: Arc<Counters>,
}

#[derive(Clone)]
struct PacketSender {
    secret_key: SecretKey,
    identity: PunchIdentity,
    role: PunchRole,
}

impl PacketSender {
    async fn send(
        &self,
        socket: &UdpSocket,
        counters: &Counters,
        kind: PacketKind,
        index: u16,
        destination: SocketAddr,
    ) -> Result<(), PunchError> {
        let packet = encode_packet(&self.secret_key, self.identity, self.role, kind, index);
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
}

#[derive(Clone)]
struct TargetReceiverContext {
    events: mpsc::Sender<TargetEvent>,
    selected_sender: watch::Sender<Option<u16>>,
    selected_receiver: watch::Receiver<Option<u16>>,
    selection: Arc<Mutex<Option<(u16, SocketAddrV4)>>>,
    packet_sender: PacketSender,
    peer_id: EndpointId,
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
            &discovered.qad_plan,
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
        let receiver_context = TargetReceiverContext {
            events: event_sender,
            selected_sender,
            selected_receiver,
            selection: selection.clone(),
            packet_sender: PacketSender {
                secret_key: self.secret_key.clone(),
                identity: self.identity,
                role: PunchRole::Target,
            },
            peer_id: self.peer_id,
        };
        for local in &self.sockets {
            let local = local.clone();
            let receiver_context = receiver_context.clone();
            self.workers
                .spawn(async move { target_receiver(local, receiver_context).await });
        }
        drop(receiver_context);

        let peer_addrs = unique_observed_addrs(&self.peer_observations)?;
        let packet_sender = PacketSender {
            secret_key: self.secret_key.clone(),
            identity: self.identity,
            role: PunchRole::Target,
        };
        for local in &self.sockets {
            for peer_addr in &peer_addrs {
                packet_sender
                    .send(
                        &local.socket,
                        &local.counters,
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
        let packet_sender = PacketSender {
            secret_key: self.secret_key.clone(),
            identity: self.identity,
            role: PunchRole::Client,
        };
        for address in &known_addrs {
            packet_sender
                .send(
                    socket,
                    counters,
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
                    let (len, source) = received.map_err(io_punch_error)?;
                    counters.received(len);
                    let Some(source) = ipv4_source(source) else { continue };
                    let Some(packet) = decode_packet(
                        &buffer[..len], self.identity, self.peer_id, PunchRole::Target
                    ) else { continue };
                    match packet.kind {
                        PacketKind::Offer if usize::from(packet.index) < TARGET_SOCKET_COUNT => {
                            if selected.is_none() {
                                selected = Some((packet.index, source));
                                packet_sender.send(
                                    socket,
                                    counters,
                                    PacketKind::Select,
                                    packet.index,
                                    SocketAddr::V4(source),
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
                    packet_sender.send(
                        socket,
                        counters,
                        PacketKind::Probe,
                        PROBE_INDEX,
                        SocketAddr::V4(SocketAddrV4::new(self.target_ip, port)),
                    ).await?;
                    random_probes_sent += 1;
                }
                _ = select_tick.tick(), if selected.is_some() && !confirmed => {
                    let (index, address) = selected.expect("selection guard checked");
                    packet_sender.send(
                        socket,
                        counters,
                        PacketKind::Select,
                        index,
                        SocketAddr::V4(address),
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
    local: PunchSocket,
    mut context: TargetReceiverContext,
) -> Result<(), PunchError> {
    let index = local.index;
    let local_socket = local.local_socket;
    let socket = local.socket;
    let counters = local.counters;
    let identity = context.packet_sender.identity;
    let peer_id = context.peer_id;
    let mut buffer = [0u8; 2048];
    loop {
        if context
            .selected_receiver
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
                        context.packet_sender.send(
                            &socket,
                            &counters,
                            PacketKind::Offer,
                            index,
                            SocketAddr::V4(source),
                        ).await?;
                    }
                    PacketKind::Select if packet.index == index => {
                        let source_selection = {
                            let mut current = context.selection.lock().expect("punch selection mutex poisoned");
                            match *current {
                                None => {
                                    *current = Some((index, source));
                                    let _ = context.selected_sender.send_replace(Some(index));
                                    Some(true)
                                }
                                Some((selected, selected_source)) if selected == index && selected_source == source => Some(false),
                                _ => None,
                            }
                        };
                        if source_selection.is_none() {
                            continue;
                        }
                        context.packet_sender.send(
                            &socket,
                            &counters,
                            PacketKind::Confirm,
                            index,
                            SocketAddr::V4(source),
                        ).await?;
                        if source_selection == Some(true) {
                            context.events.send(TargetEvent::Selected(PunchSelection {
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
            changed = context.selected_receiver.changed() => {
                let selected = *context.selected_receiver.borrow_and_update();
                if changed.is_err() || selected.is_some_and(|selected| selected != index) {
                    return Ok(());
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::super::super::qad::QadReflector;
    use super::super::discovery::{PRIVATE_QAD_PORT, default_qad_configs};
    use super::*;
    use crate::transport::QadPlan;
    use uuid::Uuid;

    fn private_qad_plan() -> QadPlan {
        QadPlan::PrivateAndOfficial {
            server_url: "https://192.0.2.11:9443".parse().unwrap(),
            udp_port: PRIVATE_QAD_PORT,
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
        let qad_plan = private_qad_plan();
        let mut target = PreparedPunch::prepare(
            PunchRole::Target,
            identity,
            target_key,
            DiscoveredUdpSocket {
                socket: target_socket,
                local_socket: target_local,
                observations: target_observations.clone(),
                qad_plan: qad_plan.clone(),
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
                qad_plan,
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
                qad_plan: private_qad_plan(),
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
