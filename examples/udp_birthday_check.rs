use std::{
    collections::HashSet,
    fs::{self, File},
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket as StdUdpSocket},
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, SecretKey, TransportAddr,
    Watcher as _,
    endpoint::{
        Connection, NetReportConfig, PortmapperConfig, RecvStream, SendStream, VarInt, presets,
    },
};
use iroh_relay::{RelayQuicConfig, tls::CaTlsConfig};
use kmesh::transport::{QadReflector, observe_ipv4_mappings};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader},
    net::UdpSocket,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval, timeout_at},
};
use uuid::Uuid;

const B_RELAY_URL: &str = "https://192.0.2.11:9443/";
const B_QAD_PORT: u16 = 3478;
const ALPN: &[u8] = b"kmesh/udp-birthday-check/1";
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
const TARGET_PROBE_TIMEOUT: Duration = Duration::from_secs(38);
const CLIENT_PROBE_TIMEOUT: Duration = Duration::from_secs(35);
const CLIENT_SCAN_PORTS: usize = 1000;
const CLIENT_SCAN_INTERVAL: Duration = Duration::from_millis(15);
const SELECT_RETRY_INTERVAL: Duration = Duration::from_millis(150);
const MAX_TARGET_SOCKETS: usize = 257;
const SELECT_NONE: usize = usize::MAX;
const MAGIC: &[u8; 8] = b"KMBDAY01";
const HEADER_LEN: usize = 92;
const PACKET_LEN: usize = HEADER_LEN + 64;
const PROBE_INDEX: u16 = u16::MAX;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Target,
    Client,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Client => "client",
        }
    }

    fn wire(self) -> u8 {
        match self {
            Self::Target => 0,
            Self::Client => 1,
        }
    }
}

struct Args {
    role: Role,
    ca_file: PathBuf,
    local_ip: Ipv4Addr,
    endpoint_secret_key_file: PathBuf,
}

#[derive(Deserialize)]
struct Paired {
    event: String,
    sid: String,
    target_id: String,
    client_id: String,
    peer_local_socket: SocketAddr,
    peer_observations: Vec<Value>,
}

#[derive(Clone, Copy)]
struct RawIdentity {
    sid: Uuid,
    target_id: EndpointId,
    client_id: EndpointId,
    peer_id: EndpointId,
}

#[derive(Deserialize)]
struct HandOff {
    event: String,
    self_observed_addr: SocketAddr,
    peer_observed_addr: SocketAddr,
}

#[derive(Deserialize)]
struct ConnectGate {
    event: String,
    peer_endpoint_id: String,
    peer_endpoint_addr: EndpointAddr,
}

#[derive(Clone, Copy)]
enum PacketKind {
    Probe = 1,
    Offer = 2,
    Select = 3,
    Confirm = 4,
}

impl PacketKind {
    fn parse(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Probe),
            2 => Some(Self::Offer),
            3 => Some(Self::Select),
            4 => Some(Self::Confirm),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Packet {
    kind: PacketKind,
    index: u16,
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

    fn json(&self) -> Value {
        json!({
            "tx_datagrams": self.tx_datagrams.load(Ordering::Relaxed),
            "tx_bytes": self.tx_bytes.load(Ordering::Relaxed),
            "rx_datagrams": self.rx_datagrams.load(Ordering::Relaxed),
            "rx_bytes": self.rx_bytes.load(Ordering::Relaxed)
        })
    }
}

#[derive(Clone)]
struct LocalSocket {
    index: u16,
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    counters: Arc<Counters>,
}

#[derive(Clone)]
struct PacketSender {
    secret_key: SecretKey,
    identity: RawIdentity,
    role: Role,
}

impl PacketSender {
    async fn send(
        &self,
        socket: &UdpSocket,
        counters: &Counters,
        kind: PacketKind,
        index: u16,
        destination: SocketAddr,
    ) -> Result<()> {
        let packet = encode_packet(
            &self.secret_key,
            self.identity.sid,
            self.identity.target_id,
            self.identity.client_id,
            self.role,
            kind,
            index,
        );
        let sent = socket
            .send_to(&packet, destination)
            .await
            .with_context(|| format!("send signed UDP packet to {destination}"))?;
        ensure!(
            sent == PACKET_LEN,
            "UDP socket sent an incomplete diagnostic datagram"
        );
        counters.sent(sent);
        Ok(())
    }
}

struct TargetReceiverContext {
    local: LocalSocket,
    events: tokio::sync::mpsc::Sender<TargetEvent>,
    selected: Arc<AtomicUsize>,
    packet_sender: PacketSender,
}

struct RawSelection {
    index: u16,
    local_socket: SocketAddr,
    peer_observed_addr: SocketAddr,
    counters: Arc<Counters>,
    known_candidate_probes_sent: usize,
    random_port_probes_sent: usize,
}

enum TargetEvent {
    Selected(RawSelection),
    Failed(String),
}

struct TargetRawRuntime {
    workers: JoinSet<()>,
    events: tokio::sync::mpsc::Receiver<TargetEvent>,
}

#[derive(Clone)]
struct Mapping {
    local_socket: SocketAddr,
    observed_addr: SocketAddr,
    reflector_addr: SocketAddr,
    reflector_server_name: String,
    tx_datagrams: u64,
    tx_bytes: u64,
    rx_datagrams: u64,
    rx_bytes: u64,
    handshake_confirmed: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = emit(json!({"event":"failure","error":format!("{error:#}")}));
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args = parse_args()?;
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow!("install rustls ring provider"))?;
    }
    let encoded = fs::read_to_string(&args.endpoint_secret_key_file)
        .context("read registered Endpoint secret key")?;
    let secret_bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("decode registered Endpoint secret key")?;
    let secret_bytes: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| anyhow!("Endpoint secret key must contain 32 bytes"))?;
    let secret_key = SecretKey::from_bytes(&secret_bytes);
    let local_endpoint_id = secret_key.public();
    let mut ca_reader = BufReader::new(File::open(&args.ca_file).context("open B CA PEM file")?);
    let ca_certs = rustls_pemfile::certs(&mut ca_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse B CA PEM certificates")?;
    ensure!(!ca_certs.is_empty(), "B CA file contains no certificates");
    let ca_tls = CaTlsConfig::default().with_extra_roots(ca_certs);
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let qad_tls = ca_tls
        .client_config(crypto_provider)
        .context("build QAD TLS client config with B CA and ring")?;
    let official_relay = RelayMode::Default
        .relay_map()
        .relays::<Vec<_>>()
        .into_iter()
        .next()
        .context("Iroh SDK default relay map has no official relay")?;
    let official_qad = official_relay
        .quic
        .as_ref()
        .context("Iroh official relay has no QAD port")?;
    ensure!(
        official_qad.port == 7842,
        "Iroh official QAD port differs from 7842"
    );
    let official_server_name = official_relay
        .url
        .host_str()
        .context("Iroh official relay URL has no TLS hostname")?
        .to_owned();
    let official_addr = (official_server_name.as_str(), official_qad.port)
        .to_socket_addrs()
        .context("resolve the first Iroh official QAD relay")?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(address),
            SocketAddr::V6(_) => None,
        })
        .context("Iroh official QAD relay has no IPv4 address")?;
    let reflectors = [
        QadReflector {
            addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 11), B_QAD_PORT),
            server_name: "192.0.2.11".to_owned(),
        },
        QadReflector {
            addr: official_addr,
            server_name: official_server_name,
        },
    ];

    let std_socket = StdUdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(args.local_ip, 0)))
        .context("bind the single IPv4 UDP socket for both QAD reflectors")?;
    let (std_socket, observations) = timeout_at(
        deadline,
        observe_ipv4_mappings(std_socket, qad_tls, &reflectors, deadline),
    )
    .await
    .context("QAD mapping observation exceeded the 60-second deadline")?
    .context("observe B and official QAD mappings on the original socket")?;
    let local_socket = std_socket.local_addr().context("read QAD local socket")?;
    ensure!(
        local_socket
            == SocketAddr::V4(
                observations
                    .first()
                    .context("QAD returned no observations")?
                    .local_socket,
            ),
        "QAD observation local tuple differs from the original socket"
    );
    let own_observations = observations
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("serialize complete QAD observations")?;
    emit(json!({
        "event":"ready",
        "role":args.role.as_str(),
        "endpoint_id":local_endpoint_id.to_string(),
        "local_socket":local_socket,
        "observations":own_observations,
        "configured_relay_url":B_RELAY_URL
    }))?;

    let mut control = AsyncBufReader::new(tokio::io::stdin());
    let paired_value = read_control(&mut control, "paired", deadline).await?;
    let paired: Paired = serde_json::from_value(paired_value).context("decode paired metadata")?;
    ensure!(paired.event == "paired", "expected paired metadata");
    let sid = Uuid::parse_str(&paired.sid).context("parse paired session UUID")?;
    let target_id: EndpointId = paired
        .target_id
        .parse()
        .context("parse target EndpointId")?;
    let client_id: EndpointId = paired
        .client_id
        .parse()
        .context("parse client EndpointId")?;
    let expected_local_id = match args.role {
        Role::Target => target_id,
        Role::Client => client_id,
    };
    ensure!(
        local_endpoint_id == expected_local_id,
        "configured diagnostic key does not match the paired local EndpointId"
    );
    let peer_id = match args.role {
        Role::Target => client_id,
        Role::Client => target_id,
    };
    ensure!(
        paired.peer_local_socket.is_ipv4(),
        "paired peer local socket must be IPv4"
    );
    let own_mappings = mapping_views(&own_observations)?;
    let peer_mappings = mapping_views(&paired.peer_observations)?;
    validate_reflector_sources(&own_mappings, &reflectors[1].server_name)?;
    validate_reflector_sources(&peer_mappings, &reflectors[1].server_name)?;
    validate_mode2_inputs(args.role, &own_mappings, &peer_mappings)?;
    let (target_mappings, client_mappings) = match args.role {
        Role::Target => (&own_mappings, &peer_mappings),
        Role::Client => (&peer_mappings, &own_mappings),
    };
    let target_ip = validate_target_mapping(target_mappings)?;
    validate_client_mapping(client_mappings)?;
    ensure!(
        own_mappings
            .iter()
            .all(|mapping| mapping.local_socket == local_socket),
        "QAD observations do not refer to the original socket"
    );
    ensure!(
        peer_mappings
            .iter()
            .all(|mapping| mapping.local_socket == paired.peer_local_socket),
        "peer QAD observations do not refer to its reported original socket"
    );

    let std_socket = std_socket;
    let local_sockets = bind_raw_sockets(args.role, std_socket, args.local_ip)?;
    emit(json!({
        "event":"raw_ready",
        "role":args.role.as_str(),
        "endpoint_id":local_endpoint_id.to_string(),
        "sockets":local_sockets.iter().map(|socket| json!({
            "index":socket.index,
            "local_socket":socket.addr
        })).collect::<Vec<_>>()
    }))?;
    read_control(&mut control, "start_probe", deadline).await?;

    let raw_identity = RawIdentity {
        sid,
        target_id,
        client_id,
        peer_id,
    };
    let selection = match args.role {
        Role::Target => {
            let mut runtime = start_target_raw(
                &local_sockets,
                client_mappings,
                PacketSender {
                    secret_key: secret_key.clone(),
                    identity: raw_identity,
                    role: Role::Target,
                },
            )
            .await?;
            let raw_deadline = std::cmp::min(Instant::now() + TARGET_PROBE_TIMEOUT, deadline);
            let selected = match timeout_at(raw_deadline, runtime.events.recv()).await {
                Err(_) => {
                    emit(json!({
                        "event":"raw_timeout",
                        "role":"target",
                        "receiver_socket_count":local_sockets.len(),
                        "socket_counters":local_sockets.iter().map(|socket| json!({
                            "index":socket.index,
                            "local_socket":socket.addr,
                            "counters":socket.counters.json()
                        })).collect::<Vec<_>>()
                    }))?;
                    bail!("target mode-2 raw selection timed out");
                }
                Ok(None) => bail!("all target raw receiver tasks stopped before selection"),
                Ok(Some(TargetEvent::Selected(selected))) => selected,
                Ok(Some(TargetEvent::Failed(error))) => {
                    bail!("target raw receiver failed: {error}")
                }
            };
            emit_raw_selected(args.role, &selected)?;
            let hand_off_value = read_control(&mut control, "hand_off", deadline).await?;
            let hand_off: HandOff =
                serde_json::from_value(hand_off_value).context("decode hand_off gate")?;
            ensure!(hand_off.event == "hand_off", "expected hand_off gate");
            ensure!(
                hand_off.peer_observed_addr == selected.peer_observed_addr,
                "hand_off peer_observed_addr differs from the raw selected peer tuple"
            );
            runtime.workers.abort_all();
            while runtime.workers.join_next().await.is_some() {}
            (selected, hand_off)
        }
        Role::Client => {
            let selected = run_client_raw(
                &local_sockets[0],
                target_mappings,
                target_ip,
                PacketSender {
                    secret_key: secret_key.clone(),
                    identity: raw_identity,
                    role: Role::Client,
                },
                deadline,
            )
            .await?;
            emit_raw_selected(args.role, &selected)?;
            let hand_off_value = read_control(&mut control, "hand_off", deadline).await?;
            let hand_off: HandOff =
                serde_json::from_value(hand_off_value).context("decode hand_off gate")?;
            ensure!(hand_off.event == "hand_off", "expected hand_off gate");
            ensure!(
                hand_off.peer_observed_addr == selected.peer_observed_addr,
                "hand_off peer_observed_addr differs from the raw selected peer tuple"
            );
            (selected, hand_off)
        }
    };

    validate_handoff_addresses(&selection.0, &selection.1)?;
    let selected_local_socket = selection.0.local_socket;
    let selected_counters = selection.0.counters.json();
    drop(local_sockets);
    emit(json!({
        "event":"raw_sockets_closed",
        "role":args.role.as_str(),
        "selected_index":selection.0.index,
        "local_socket":selected_local_socket,
        "selected_counters":selected_counters,
        "same_tuple_iroh_will_use_new_socket_object":true
    }))?;

    let endpoint = bind_iroh_endpoint(
        secret_key,
        ca_tls,
        args.local_ip,
        selected_local_socket,
        selection.1.self_observed_addr,
        deadline,
    )
    .await?;
    let endpoint_addr = endpoint.addr();
    let home_relay = endpoint_addr
        .relay_urls()
        .next()
        .map(ToString::to_string)
        .context("Iroh EndpointAddr has no home relay")?;
    emit(json!({
        "event":"native_ready",
        "role":args.role.as_str(),
        "endpoint_id":endpoint.id().to_string(),
        "local_socket":selected_local_socket,
        "endpoint_addr":endpoint_addr,
        "home_relay_url":home_relay
    }))?;

    let connect_value = read_control(&mut control, "connect", deadline).await?;
    let connect_gate: ConnectGate =
        serde_json::from_value(connect_value).context("decode connect gate")?;
    ensure!(connect_gate.event == "connect", "expected connect gate");
    let expected_peer_id: EndpointId = connect_gate
        .peer_endpoint_id
        .parse()
        .context("parse connect peer EndpointId")?;
    ensure!(
        expected_peer_id == peer_id,
        "connect peer identity differs from paired identity"
    );
    ensure!(
        connect_gate.peer_endpoint_addr.id == peer_id,
        "connect EndpointAddr identity differs from paired peer identity"
    );
    ensure!(
        connect_gate
            .peer_endpoint_addr
            .ip_addrs()
            .any(|addr| { addr.is_ipv4() && addr == &selection.1.peer_observed_addr }),
        "peer EndpointAddr omits the mode-2 raw observed IPv4 address"
    );
    let private_relay_url = B_RELAY_URL.parse::<iroh::RelayUrl>()?;
    let peer_relay_urls = connect_gate
        .peer_endpoint_addr
        .relay_urls()
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        !peer_relay_urls.is_empty() && peer_relay_urls.iter().all(|url| url == &private_relay_url),
        "peer EndpointAddr contains a relay outside the configured private relay"
    );
    let connection = connect_peer(
        args.role,
        &endpoint,
        connect_gate.peer_endpoint_addr,
        deadline,
    )
    .await?;
    ensure!(
        connection.remote_id() == peer_id,
        "Iroh connection authenticated an unexpected peer EndpointId"
    );
    let selected_path_before = wait_for_ipv4_direct(&connection, deadline).await?;
    emit(json!({
        "event":"direct_selected",
        "role":args.role.as_str(),
        "endpoint_id":endpoint.id().to_string(),
        "peer_endpoint_id":connection.remote_id().to_string(),
        "selected_path":selected_path_before.json(),
        "paths":paths_json(&connection)
    }))?;

    read_control(&mut control, "go_data", deadline).await?;
    let paths_before = path_samples(&connection);
    let selected_before =
        selected_direct(&paths_before).context("direct IPv4 path disappeared before data")?;
    let local_opens_stream = args.role == Role::Client;
    let (mut send, mut recv) = if local_opens_stream {
        timeout_at(deadline, connection.open_bi())
            .await
            .context("open QUIC diagnostic stream deadline")??
    } else {
        timeout_at(deadline, connection.accept_bi())
            .await
            .context("accept QUIC diagnostic stream deadline")??
    };
    let nonce_rounds = timeout_at(deadline, exchange_nonces(args.role, &mut send, &mut recv))
        .await
        .context("nonce and FIN exchange deadline")??;
    drop(send);
    drop(recv);
    let paths_after = path_samples(&connection);
    let selected_after = selected_direct(&paths_after);
    let deltas = path_deltas(&paths_before, &paths_after);
    let selected_delta = deltas
        .iter()
        .find(|delta| delta["path_id"].as_str() == Some(&selected_before.id));
    let direct_bytes_grew = selected_delta.is_some_and(|delta| {
        delta["tx_bytes_delta"].as_u64().unwrap_or(0) > 0
            && delta["rx_bytes_delta"].as_u64().unwrap_or(0) > 0
    });
    let nonce_checks = nonce_rounds
        .iter()
        .filter_map(|round| round["echo_matches"].as_bool())
        .collect::<Vec<_>>();
    let peer_nonce_echoes = nonce_rounds
        .iter()
        .filter(|round| round["echo_sent"] == true)
        .count();
    let echoes_match = nonce_checks.len() == 3 && nonce_checks.iter().all(|matches| *matches);
    let peer_nonces_echoed = peer_nonce_echoes == 3;
    let fin_complete = nonce_rounds.iter().all(|round| {
        round["fin_complete"] == true
            && round["peer_eof"] == true
            && round["send_stopped_ok"] == true
    });
    let pass = echoes_match
        && peer_nonces_echoed
        && fin_complete
        && direct_bytes_grew
        && selected_after.is_some_and(|path| path.id == selected_before.id);
    emit(json!({
        "event":"nonce_result",
        "role":args.role.as_str(),
        "nonce_rounds":nonce_rounds,
        "nonce_echoes_match":echoes_match,
        "peer_nonces_echoed":peer_nonces_echoed,
        "fin_complete":fin_complete,
        "peer_eof":fin_complete,
        "send_stopped_ok":fin_complete,
        "selected_direct_before":selected_before.json(),
        "selected_direct_after":selected_after.map(|path| path.json()),
        "path_deltas":deltas,
        "direct_path_udp_bytes_grew_both_directions":direct_bytes_grew,
        "pass":pass
    }))?;
    ensure!(
        pass,
        "direct QUIC path, bidirectional nonce, or FIN evidence failed"
    );
    connection.close(VarInt::from_u32(0), b"UDP birthday diagnostic complete");
    timeout_at(deadline, endpoint.close())
        .await
        .context("close diagnostic Iroh endpoint before deadline")?;
    emit(json!({
        "event":"complete",
        "role":args.role.as_str(),
        "endpoint_id":local_endpoint_id.to_string(),
        "same_tuple_reused":true,
        "same_socket_object_reused":false,
        "nonce_echoes_match":echoes_match,
        "peer_nonces_echoed":peer_nonces_echoed,
        "fin_complete":fin_complete,
        "peer_eof":fin_complete,
        "send_stopped_ok":fin_complete,
        "direct_path_udp_bytes_grew_both_directions":direct_bytes_grew,
        "pass":true
    }))?;
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut role = None;
    let mut ca_file = None;
    let mut local_ip = None;
    let mut endpoint_secret_key_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--role" => {
                role = Some(match args.next().as_deref() {
                    Some("target") => Role::Target,
                    Some("client") => Role::Client,
                    _ => bail!("--role must be target or client"),
                })
            }
            "--ca-file" => ca_file = args.next().map(PathBuf::from),
            "--local-ip" => {
                local_ip = Some(
                    args.next()
                        .context("--local-ip requires an IPv4 address")?
                        .parse::<Ipv4Addr>()
                        .context("parse --local-ip")?,
                )
            }
            "--endpoint-secret-key-file" => {
                endpoint_secret_key_file = args.next().map(PathBuf::from)
            }
            _ => bail!(
                "usage: udp_birthday_check --role target|client --ca-file <PEM> --local-ip <IPv4> --endpoint-secret-key-file <FILE>"
            ),
        }
    }
    Ok(Args {
        role: role.context("--role is required")?,
        ca_file: ca_file.context("--ca-file is required")?,
        local_ip: local_ip.context("--local-ip is required")?,
        endpoint_secret_key_file: endpoint_secret_key_file
            .context("--endpoint-secret-key-file is required")?,
    })
}

fn bind_raw_sockets(
    role: Role,
    std_socket: StdUdpSocket,
    local_ip: Ipv4Addr,
) -> Result<Vec<LocalSocket>> {
    let mut sockets = Vec::with_capacity(if role == Role::Target {
        MAX_TARGET_SOCKETS
    } else {
        1
    });
    let local_addr = std_socket
        .local_addr()
        .context("read original QAD UDP tuple")?;
    let original =
        UdpSocket::from_std(std_socket).context("take ownership of original QAD UDP socket")?;
    sockets.push(LocalSocket {
        index: 0,
        addr: local_addr,
        socket: Arc::new(original),
        counters: Arc::new(Counters::default()),
    });
    if role == Role::Target {
        for index in 1..MAX_TARGET_SOCKETS {
            let socket = StdUdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(local_ip, 0)))
                .with_context(|| format!("bind mode-2 receiver socket {index}"))?;
            socket
                .set_nonblocking(true)
                .with_context(|| format!("set mode-2 receiver socket {index} nonblocking"))?;
            let addr = socket
                .local_addr()
                .context("read mode-2 receiver local tuple")?;
            sockets.push(LocalSocket {
                index: index as u16,
                addr,
                socket: Arc::new(
                    UdpSocket::from_std(socket).context("convert receiver UDP socket")?,
                ),
                counters: Arc::new(Counters::default()),
            });
        }
    }
    Ok(sockets)
}

fn mapping_views(values: &[Value]) -> Result<Vec<Mapping>> {
    values
        .iter()
        .map(|value| {
            let local_socket = json_socket(value, "local_socket")?;
            let observed_addr = json_socket(value, "observed_addr")?;
            let reflector_addr = value
                .get("reflector")
                .and_then(|reflector| reflector.get("addr"))
                .cloned()
                .context("QAD observation has no reflector.addr")
                .and_then(|addr| {
                    serde_json::from_value(addr).context("parse QAD reflector address")
                })?;
            let reflector_server_name = value
                .get("reflector")
                .and_then(|reflector| reflector.get("server_name"))
                .and_then(Value::as_str)
                .context("QAD observation has no reflector.server_name")?
                .to_owned();
            let handshake_confirmed = value
                .get("handshake_confirmed")
                .and_then(Value::as_bool)
                .context("QAD observation has no handshake_confirmed flag")?;
            let tx_datagrams = observation_counter(value, "udp_tx_datagrams")?;
            let tx_bytes = observation_counter(value, "udp_tx_bytes")?;
            let rx_datagrams = observation_counter(value, "udp_rx_datagrams")?;
            let rx_bytes = observation_counter(value, "udp_rx_bytes")?;
            Ok(Mapping {
                local_socket,
                observed_addr,
                reflector_addr,
                reflector_server_name,
                tx_datagrams,
                tx_bytes,
                rx_datagrams,
                rx_bytes,
                handshake_confirmed,
            })
        })
        .collect()
}

fn json_socket(value: &Value, key: &str) -> Result<SocketAddr> {
    serde_json::from_value(
        value
            .get(key)
            .cloned()
            .with_context(|| format!("QAD observation has no {key}"))?,
    )
    .with_context(|| format!("parse QAD observation {key}"))
}

fn observation_counter(value: &Value, flat: &str) -> Result<u64> {
    value
        .get(flat)
        .and_then(Value::as_u64)
        .with_context(|| format!("QAD observation has no {flat}"))
}

fn validate_mode2_inputs(role: Role, own: &[Mapping], peer: &[Mapping]) -> Result<()> {
    ensure!(
        own.len() == 2 && peer.len() == 2,
        "invalid_strategy: require exactly two QAD observations on each side"
    );
    for mapping in own.iter().chain(peer) {
        ensure!(
            mapping.local_socket.is_ipv4(),
            "invalid_strategy: QAD local socket must be IPv4"
        );
        ensure!(
            mapping.observed_addr.is_ipv4(),
            "invalid_strategy: observed QAD address must be IPv4"
        );
        ensure!(
            mapping.reflector_addr.is_ipv4(),
            "invalid_strategy: QAD reflector must be IPv4"
        );
        ensure!(
            mapping.handshake_confirmed,
            "invalid_strategy: QAD reflector handshake was not confirmed"
        );
        ensure!(
            mapping.tx_datagrams > 0 && mapping.tx_bytes > 0,
            "invalid_strategy: QAD sent no UDP bytes"
        );
        ensure!(
            mapping.rx_datagrams > 0 && mapping.rx_bytes > 0,
            "invalid_strategy: QAD received no UDP bytes"
        );
    }
    let (target, client) = match role {
        Role::Target => (own, peer),
        Role::Client => (peer, own),
    };
    validate_target_mapping(target)?;
    validate_client_mapping(client)?;
    Ok(())
}

fn validate_reflector_sources(mappings: &[Mapping], official_server_name: &str) -> Result<()> {
    ensure!(
        mappings.len() == 2,
        "invalid_strategy: exactly two fixed QAD reflectors are required"
    );
    let b_reflector = mappings.iter().find(|mapping| {
        mapping.reflector_addr
            == SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 0, 2, 11),
                B_QAD_PORT,
            ))
    });
    ensure!(
        b_reflector.is_some_and(|mapping| mapping.reflector_server_name == "192.0.2.11"),
        "invalid_strategy: QAD observations omit the fixed B:3478 reflector"
    );
    let official_reflector = mappings
        .iter()
        .find(|mapping| mapping.reflector_addr.port() == 7842);
    ensure!(
        official_reflector
            .is_some_and(|mapping| { mapping.reflector_server_name == official_server_name }),
        "invalid_strategy: QAD observations omit the Iroh SDK official reflector on UDP 7842"
    );
    Ok(())
}

fn validate_target_mapping(target: &[Mapping]) -> Result<Ipv4Addr> {
    ensure!(
        target.len() == 2,
        "invalid_strategy: target needs two reflector observations"
    );
    ensure!(
        target[0].reflector_addr.port() == B_QAD_PORT && target[1].reflector_addr.port() == 7842
            || target[1].reflector_addr.port() == B_QAD_PORT
                && target[0].reflector_addr.port() == 7842,
        "invalid_strategy: target observations must use B:3478 and official QAD:7842"
    );
    let target_ip = match target[0].observed_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => bail!("invalid_strategy: target public mapping must be IPv4"),
    };
    ensure!(
        target[1].observed_addr.ip() == IpAddr::V4(target_ip),
        "invalid_strategy: target mappings use different public IPv4 addresses"
    );
    let difference = target[0]
        .observed_addr
        .port()
        .abs_diff(target[1].observed_addr.port());
    ensure!(
        difference > 5,
        "invalid_strategy: target port difference does not meet current mode-2 condition"
    );
    ensure!(
        target[0].local_socket == target[1].local_socket,
        "invalid_strategy: target QAD observations came from different local sockets"
    );
    Ok(target_ip)
}

fn validate_client_mapping(client: &[Mapping]) -> Result<()> {
    ensure!(
        client.len() == 2,
        "invalid_strategy: client needs two reflector observations"
    );
    ensure!(
        client[0].reflector_addr.port() == B_QAD_PORT && client[1].reflector_addr.port() == 7842
            || client[1].reflector_addr.port() == B_QAD_PORT
                && client[0].reflector_addr.port() == 7842,
        "invalid_strategy: client observations must use B:3478 and official QAD:7842"
    );
    ensure!(
        client[0].observed_addr == client[1].observed_addr,
        "invalid_strategy: client public mapping is not stable across the two reflectors"
    );
    ensure!(
        client[0].local_socket == client[1].local_socket,
        "invalid_strategy: client QAD observations came from different local sockets"
    );
    Ok(())
}

fn validate_handoff_addresses(selected: &RawSelection, hand_off: &HandOff) -> Result<()> {
    ensure!(
        hand_off.self_observed_addr.is_ipv4(),
        "handoff self address must be IPv4"
    );
    ensure!(
        hand_off.peer_observed_addr.is_ipv4(),
        "handoff peer address must be IPv4"
    );
    ensure!(
        hand_off.peer_observed_addr == selected.peer_observed_addr,
        "handoff peer address differs from selected raw peer tuple"
    );
    ensure!(
        selected.local_socket.is_ipv4(),
        "selected raw local socket must be IPv4"
    );
    Ok(())
}

fn emit_raw_selected(role: Role, selected: &RawSelection) -> Result<()> {
    emit(json!({
        "event":"raw_selected",
        "role":role.as_str(),
        "index":selected.index,
        "local_socket":selected.local_socket,
        "peer_observed_addr":selected.peer_observed_addr,
        "counters":selected.counters.json(),
        "known_candidate_probes_sent":selected.known_candidate_probes_sent,
        "random_port_probes_sent":selected.random_port_probes_sent
    }))
}

async fn start_target_raw(
    sockets: &[LocalSocket],
    client_mappings: &[Mapping],
    packet_sender: PacketSender,
) -> Result<TargetRawRuntime> {
    ensure!(
        sockets.len() == MAX_TARGET_SOCKETS,
        "target must bind exactly 257 mode-2 sockets"
    );
    let peer_addrs = unique_observed_addrs(client_mappings);
    let selected = Arc::new(AtomicUsize::new(SELECT_NONE));
    let (event_tx, event_rx) = tokio::sync::mpsc::channel(8);
    let mut workers = JoinSet::new();
    for local in sockets {
        let failure_tx = event_tx.clone();
        let context = TargetReceiverContext {
            local: local.clone(),
            events: failure_tx.clone(),
            selected: selected.clone(),
            packet_sender: packet_sender.clone(),
        };
        workers.spawn(async move {
            if let Err(error) = target_receiver(context).await {
                let _ = failure_tx
                    .send(TargetEvent::Failed(format!("{error:#}")))
                    .await;
            }
        });
    }
    drop(event_tx);

    for local in sockets {
        for peer_addr in &peer_addrs {
            packet_sender
                .send(
                    &local.socket,
                    &local.counters,
                    PacketKind::Offer,
                    local.index,
                    *peer_addr,
                )
                .await
                .with_context(|| {
                    format!("send initial Offer from target socket {}", local.index)
                })?;
        }
    }

    Ok(TargetRawRuntime {
        workers,
        events: event_rx,
    })
}

async fn target_receiver(context: TargetReceiverContext) -> Result<()> {
    let TargetReceiverContext {
        local,
        events,
        selected,
        packet_sender,
    } = context;
    let index = local.index;
    let socket = local.socket;
    let counters = local.counters;
    let local_addr = local.addr;
    let mut buffer = [0u8; 2048];
    loop {
        let (len, source) = socket
            .recv_from(&mut buffer)
            .await
            .context("receive raw target datagram")?;
        counters.received(len);
        let Some(packet) = decode_packet(
            &buffer[..len],
            packet_sender.identity.sid,
            packet_sender.identity.target_id,
            packet_sender.identity.client_id,
            packet_sender.identity.peer_id,
            Role::Client,
        ) else {
            continue;
        };
        match packet.kind {
            PacketKind::Probe if packet.index == PROBE_INDEX => {
                packet_sender
                    .send(&socket, &counters, PacketKind::Offer, index, source)
                    .await
                    .context("reply to valid client Probe")?;
            }
            PacketKind::Select if packet.index == index && source.is_ipv4() => {
                let current = selected.load(Ordering::Acquire);
                let won_selection = if current == SELECT_NONE {
                    selected
                        .compare_exchange(
                            SELECT_NONE,
                            usize::from(index),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                } else {
                    false
                };
                if selected.load(Ordering::Acquire) != usize::from(index) {
                    continue;
                }
                packet_sender
                    .send(&socket, &counters, PacketKind::Confirm, index, source)
                    .await
                    .context("confirm selected target socket")?;
                if won_selection {
                    events
                        .send(TargetEvent::Selected(RawSelection {
                            index,
                            local_socket: local_addr,
                            peer_observed_addr: source,
                            counters: counters.clone(),
                            known_candidate_probes_sent: 0,
                            random_port_probes_sent: 0,
                        }))
                        .await
                        .map_err(|_| anyhow!("raw selection coordinator stopped"))?;
                }
            }
            _ => {}
        }
    }
}

async fn run_client_raw(
    local: &LocalSocket,
    target_mappings: &[Mapping],
    target_ip: Ipv4Addr,
    packet_sender: PacketSender,
    deadline: Instant,
) -> Result<RawSelection> {
    let raw_deadline = std::cmp::min(Instant::now() + CLIENT_PROBE_TIMEOUT, deadline);
    let socket = local.socket.clone();
    let counters = local.counters.clone();
    let scanner_socket = socket.clone();
    let scanner_counters = counters.clone();
    let scanner_packet_sender = packet_sender.clone();
    let scanner_addrs = unique_observed_addrs(target_mappings);
    let already_probed_ports = scanner_addrs
        .iter()
        .filter_map(|address| match address {
            SocketAddr::V4(address)
                if *address.ip() == target_ip && (1024..=65534).contains(&address.port()) =>
            {
                Some(address.port())
            }
            _ => None,
        })
        .collect::<HashSet<_>>();
    let known_probe_count = Arc::new(AtomicUsize::new(0));
    let random_probe_count = Arc::new(AtomicUsize::new(0));
    let scanner_known_probe_count = known_probe_count.clone();
    let scanner_random_probe_count = random_probe_count.clone();
    let mut scanner = JoinSet::new();
    scanner.spawn(async move {
        for address in &scanner_addrs {
            scanner_packet_sender
                .send(
                    &scanner_socket,
                    &scanner_counters,
                    PacketKind::Probe,
                    PROBE_INDEX,
                    *address,
                )
                .await?;
            scanner_known_probe_count.fetch_add(1, Ordering::Relaxed);
        }
        let mut seen = already_probed_ports;
        let mut cadence = interval(CLIENT_SCAN_INTERVAL);
        cadence.set_missed_tick_behavior(MissedTickBehavior::Delay);
        for _ in 0..CLIENT_SCAN_PORTS {
            cadence.tick().await;
            let port = loop {
                let port = rand::random_range(1024u16..65535u16);
                if seen.insert(port) {
                    break port;
                }
            };
            scanner_packet_sender
                .send(
                    &scanner_socket,
                    &scanner_counters,
                    PacketKind::Probe,
                    PROBE_INDEX,
                    SocketAddr::V4(SocketAddrV4::new(target_ip, port)),
                )
                .await
                .with_context(|| format!("send bounded mode-2 probe to {target_ip}:{port}"))?;
            scanner_random_probe_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut scan_finished = false;
    let mut selected: Option<(u16, SocketAddr)> = None;
    let mut confirmed = false;
    let mut cadence = interval(SELECT_RETRY_INTERVAL);
    cadence.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut buffer = [0u8; 2048];
    let mut timeout = Box::pin(tokio::time::sleep_until(raw_deadline));
    loop {
        if confirmed {
            break;
        }
        tokio::select! {
            result = scanner.join_next(), if !scan_finished => {
                match result {
                    Some(Ok(Ok(()))) => scan_finished = true,
                    Some(Ok(Err(error))) => return Err(error).context("mode-2 client scan failed"),
                    Some(Err(error)) => return Err(anyhow!("mode-2 scanner task failed: {error}")),
                    None => bail!("mode-2 scanner stopped without completing its candidate list"),
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (len, source) = received.context("receive raw client datagram")?;
                counters.received(len);
                let Some(packet) = decode_packet(
                    &buffer[..len],
                    packet_sender.identity.sid,
                    packet_sender.identity.target_id,
                    packet_sender.identity.client_id,
                    packet_sender.identity.peer_id,
                    Role::Target
                ) else {
                    continue;
                };
                match packet.kind {
                    PacketKind::Offer if usize::from(packet.index) < MAX_TARGET_SOCKETS
                        && source.is_ipv4() => {
                        if selected.is_none() {
                            selected = Some((packet.index, source));
                            packet_sender.send(
                                &socket,
                                &counters,
                                PacketKind::Select,
                                packet.index,
                                source,
                            ).await?;
                        }
                    }
                    PacketKind::Confirm if selected == Some((packet.index, source)) => {
                        confirmed = true;
                    }
                    _ => {}
                }
            }
            _ = cadence.tick(), if selected.is_some() && !confirmed => {
                if let Some((index, address)) = selected {
                    packet_sender.send(
                        &socket,
                        &counters,
                        PacketKind::Select,
                        index,
                        address,
                    ).await?;
                }
            }
            _ = &mut timeout => {
                emit(json!({
                    "event":"raw_timeout",
                    "role":"client",
                    "local_socket":local.addr,
                    "selected_peer":selected.map(|(index, address)| json!({"index":index,"address":address})),
                    "confirmed":confirmed,
                    "known_candidate_probes_sent":known_probe_count.load(Ordering::Relaxed),
                    "random_port_probes_sent":random_probe_count.load(Ordering::Relaxed),
                    "counters":counters.json()
                }))?;
                bail!("client did not receive an authenticated target Offer and Confirm before raw deadline");
            }
        }
    }
    scanner.abort_all();
    while let Some(result) = scanner.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(anyhow!("mode-2 scanner join failed: {error}")),
            Ok(Err(error)) => return Err(error).context("mode-2 client scan failed"),
            Ok(Ok(())) => {}
        }
    }
    let (index, peer_observed_addr) = selected.context("client mode-2 selection is missing")?;
    ensure!(
        confirmed,
        "client did not receive a matching target Confirm"
    );
    Ok(RawSelection {
        index,
        local_socket: local.addr,
        peer_observed_addr,
        counters,
        known_candidate_probes_sent: known_probe_count.load(Ordering::Relaxed),
        random_port_probes_sent: random_probe_count.load(Ordering::Relaxed),
    })
}

fn encode_packet(
    secret_key: &SecretKey,
    sid: Uuid,
    target_id: EndpointId,
    client_id: EndpointId,
    role: Role,
    kind: PacketKind,
    index: u16,
) -> [u8; PACKET_LEN] {
    let mut bytes = [0u8; PACKET_LEN];
    bytes[0..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(sid.as_bytes());
    bytes[24..56].copy_from_slice(target_id.as_bytes());
    bytes[56..88].copy_from_slice(client_id.as_bytes());
    bytes[88] = role.wire();
    bytes[89] = kind as u8;
    bytes[90..92].copy_from_slice(&index.to_be_bytes());
    let signature = secret_key.sign(&bytes[..HEADER_LEN]);
    bytes[HEADER_LEN..].copy_from_slice(&signature.to_bytes());
    bytes
}

fn decode_packet(
    bytes: &[u8],
    sid: Uuid,
    target_id: EndpointId,
    client_id: EndpointId,
    peer_id: EndpointId,
    expected_role: Role,
) -> Option<Packet> {
    if bytes.len() != PACKET_LEN
        || &bytes[0..8] != MAGIC
        || &bytes[8..24] != sid.as_bytes()
        || &bytes[24..56] != target_id.as_bytes()
        || &bytes[56..88] != client_id.as_bytes()
        || bytes[88] != expected_role.wire()
    {
        return None;
    }
    let kind = PacketKind::parse(bytes[89])?;
    let index = u16::from_be_bytes(bytes[90..92].try_into().ok()?);
    let signature = iroh::Signature::try_from(&bytes[HEADER_LEN..]).ok()?;
    peer_id.verify(&bytes[..HEADER_LEN], &signature).ok()?;
    Some(Packet { kind, index })
}

fn unique_observed_addrs(mappings: &[Mapping]) -> Vec<SocketAddr> {
    let mut addresses = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        if !addresses.contains(&mapping.observed_addr) {
            addresses.push(mapping.observed_addr);
        }
    }
    addresses
}

async fn read_control(
    reader: &mut AsyncBufReader<tokio::io::Stdin>,
    expected_event: &str,
    deadline: Instant,
) -> Result<Value> {
    let mut line = String::new();
    let bytes = timeout_at(deadline, reader.read_line(&mut line))
        .await
        .with_context(|| format!("wait for {expected_event} control event"))?
        .context("read coordinator control event")?;
    ensure!(
        bytes > 0,
        "coordinator stdin closed before {expected_event}"
    );
    let value: Value =
        serde_json::from_str(&line).context("parse coordinator JSONL control event")?;
    let event = value
        .get("event")
        .and_then(Value::as_str)
        .context("coordinator event has no event field")?;
    if event == "abort" {
        bail!("coordinator aborted at {expected_event} gate");
    }
    ensure!(
        event == expected_event,
        "expected {expected_event} control event, received {event}"
    );
    Ok(value)
}

fn emit(value: Value) -> Result<()> {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value).context("serialize JSONL event")?;
    stdout.write_all(b"\n").context("write JSONL newline")?;
    stdout.flush().context("flush JSONL event")?;
    Ok(())
}

async fn bind_iroh_endpoint(
    secret_key: SecretKey,
    ca_tls: CaTlsConfig,
    local_ip: Ipv4Addr,
    selected_local_socket: SocketAddr,
    self_observed_addr: SocketAddr,
    deadline: Instant,
) -> Result<Endpoint> {
    let relay_url = B_RELAY_URL
        .parse::<iroh::RelayUrl>()
        .context("parse B private relay URL")?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Custom(RelayMap::from_iter([RelayConfig::new(
            relay_url.clone(),
            Some(RelayQuicConfig::new(B_QAD_PORT)),
        )])))
        .ca_tls_config(ca_tls)
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
        .clear_ip_transports()
        .bind_addr(SocketAddr::V4(SocketAddrV4::new(
            local_ip,
            selected_local_socket.port(),
        )))
        .context("configure Minimal Iroh endpoint on selected mode-2 local port")?;
    let endpoint = timeout_at(deadline, endpoint.bind())
        .await
        .context("bind Iroh endpoint on the selected local tuple before deadline")??;
    let bound_socket = endpoint
        .bound_sockets()
        .into_iter()
        .find(|address| address.is_ipv4() && address.ip() == IpAddr::V4(local_ip))
        .context("Iroh endpoint has no IPv4 socket on requested interface")?;
    ensure!(
        bound_socket == selected_local_socket,
        "Iroh endpoint bound {bound_socket}, expected selected raw tuple {selected_local_socket}"
    );
    timeout_at(deadline, endpoint.add_external_addr(self_observed_addr))
        .await
        .context("publish the raw peer-observed address in Iroh")?;

    let mut relay_status = endpoint.home_relay_status();
    loop {
        let statuses = relay_status.get();
        if statuses
            .iter()
            .any(|relay| relay.url() == &relay_url && relay.is_connected())
        {
            break;
        }
        if let Some(reason) = statuses
            .iter()
            .find(|relay| relay.url() == &relay_url)
            .and_then(|relay| relay.auth_denied_reason())
        {
            bail!("B private relay denied the registered EndpointId: {reason}");
        }
        timeout_at(deadline, relay_status.updated())
            .await
            .context("wait for B private relay connection")?
            .map_err(|_| anyhow!("Iroh home relay status watcher disconnected"))?;
    }

    let mut report_watcher = endpoint.net_report();
    let report = timeout_at(deadline, report_watcher.initialized())
        .await
        .context("wait for Iroh network report")?;
    let mut addr_watcher = endpoint.watch_addr();
    loop {
        if addr_watcher
            .get()
            .ip_addrs()
            .any(|candidate| candidate == &self_observed_addr)
        {
            break;
        }
        timeout_at(deadline, addr_watcher.updated())
            .await
            .context("wait for peer-observed external address publication")?
            .map_err(|_| anyhow!("Iroh endpoint address watcher disconnected"))?;
    }
    emit(json!({
        "event":"iroh_readiness",
        "endpoint_id":endpoint.id().to_string(),
        "local_socket":bound_socket,
        "private_relay_url":relay_url,
        "private_relay_connected":true,
        "net_report_udp_v4":report.udp_v4,
        "net_report_global_v4":report.global_v4,
        "published_self_observed_addr":self_observed_addr
    }))?;
    Ok(endpoint)
}

async fn connect_peer(
    role: Role,
    endpoint: &Endpoint,
    peer_addr: EndpointAddr,
    deadline: Instant,
) -> Result<Connection> {
    match role {
        Role::Client => timeout_at(deadline, endpoint.connect(peer_addr, ALPN))
            .await
            .context("client connect to target EndpointAddr")?
            .context("complete outgoing Iroh connection"),
        Role::Target => {
            let incoming = timeout_at(deadline, endpoint.accept())
                .await
                .context("target wait for incoming Iroh connection")?
                .context("Iroh endpoint closed before accepting client")?;
            timeout_at(deadline, incoming)
                .await
                .context("target complete incoming Iroh handshake")?
                .context("accept client Iroh connection")
        }
    }
}

async fn wait_for_ipv4_direct(connection: &Connection, deadline: Instant) -> Result<PathSample> {
    let mut changed = connection.paths_stream();
    loop {
        if let Some(path) = selected_direct(&path_samples(connection)) {
            return Ok(path.clone());
        }
        timeout_at(deadline, changed.next())
            .await
            .context("wait for selected IPv4 direct Iroh path")?
            .context("Iroh path event stream ended before direct selection")?;
    }
}

#[derive(Clone)]
struct PathSample {
    id: String,
    remote: String,
    local: String,
    selected: bool,
    is_ip: bool,
    is_ipv4: bool,
    tx_datagrams: u64,
    tx_bytes: u64,
    rx_datagrams: u64,
    rx_bytes: u64,
}

impl PathSample {
    fn json(&self) -> Value {
        json!({
            "path_id":self.id,
            "remote_addr":self.remote,
            "local_addr":self.local,
            "selected":self.selected,
            "is_ip":self.is_ip,
            "is_ipv4":self.is_ipv4,
            "udp_tx_datagrams":self.tx_datagrams,
            "udp_tx_bytes":self.tx_bytes,
            "udp_rx_datagrams":self.rx_datagrams,
            "udp_rx_bytes":self.rx_bytes
        })
    }
}

fn path_samples(connection: &Connection) -> Vec<PathSample> {
    connection
        .paths()
        .iter()
        .map(|path| {
            let stats = path.stats();
            let is_ipv4 =
                matches!(path.remote_addr(), TransportAddr::Ip(address) if address.is_ipv4());
            PathSample {
                id: format!("{:?}", path.id()),
                remote: path.remote_addr().to_string(),
                local: format!("{:?}", path.local_addr()),
                selected: path.is_selected(),
                is_ip: path.is_ip(),
                is_ipv4,
                tx_datagrams: stats.udp_tx.datagrams,
                tx_bytes: stats.udp_tx.bytes,
                rx_datagrams: stats.udp_rx.datagrams,
                rx_bytes: stats.udp_rx.bytes,
            }
        })
        .collect()
}

fn selected_direct(paths: &[PathSample]) -> Option<&PathSample> {
    paths
        .iter()
        .find(|path| path.selected && path.is_ip && path.is_ipv4)
}

fn paths_json(connection: &Connection) -> Vec<Value> {
    path_samples(connection)
        .iter()
        .map(PathSample::json)
        .collect()
}

fn path_deltas(before: &[PathSample], after: &[PathSample]) -> Vec<Value> {
    after
        .iter()
        .filter(|path| path.is_ip)
        .map(|current| {
            let previous = before.iter().find(|path| path.id == current.id);
            let (tx_datagrams, tx_bytes, rx_datagrams, rx_bytes) =
                previous.map_or((0, 0, 0, 0), |path| {
                    (
                        path.tx_datagrams,
                        path.tx_bytes,
                        path.rx_datagrams,
                        path.rx_bytes,
                    )
                });
            json!({
                "path_id":current.id,
                "remote_addr":current.remote,
                "selected_after":current.selected,
                "tx_datagrams_before":tx_datagrams,
                "tx_datagrams_after":current.tx_datagrams,
                "tx_datagrams_delta":current.tx_datagrams.saturating_sub(tx_datagrams),
                "tx_bytes_before":tx_bytes,
                "tx_bytes_after":current.tx_bytes,
                "tx_bytes_delta":current.tx_bytes.saturating_sub(tx_bytes),
                "rx_datagrams_before":rx_datagrams,
                "rx_datagrams_after":current.rx_datagrams,
                "rx_datagrams_delta":current.rx_datagrams.saturating_sub(rx_datagrams),
                "rx_bytes_before":rx_bytes,
                "rx_bytes_after":current.rx_bytes,
                "rx_bytes_delta":current.rx_bytes.saturating_sub(rx_bytes)
            })
        })
        .collect()
}

async fn exchange_nonces(
    role: Role,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<Vec<Value>> {
    let mut rounds = Vec::with_capacity(6);
    for round in 1..=3 {
        match role {
            Role::Client => {
                let nonce = rand::random::<[u8; 20]>();
                send.write_all(&nonce).await.context("send client nonce")?;
                send.flush().await.context("flush client nonce")?;
                let mut echo = [0u8; 20];
                recv.read_exact(&mut echo)
                    .await
                    .context("read client nonce echo")?;
                ensure!(echo == nonce, "client nonce echo mismatch");
                rounds.push(nonce_json(round, "client_to_target", &nonce, true));

                let mut target_nonce = [0u8; 20];
                recv.read_exact(&mut target_nonce)
                    .await
                    .context("read target nonce")?;
                send.write_all(&target_nonce)
                    .await
                    .context("echo target nonce")?;
                send.flush().await.context("flush target nonce echo")?;
                rounds.push(nonce_json(round, "target_to_client", &target_nonce, false));
            }
            Role::Target => {
                let mut client_nonce = [0u8; 20];
                recv.read_exact(&mut client_nonce)
                    .await
                    .context("read client nonce")?;
                send.write_all(&client_nonce)
                    .await
                    .context("echo client nonce")?;
                send.flush().await.context("flush client nonce echo")?;
                rounds.push(nonce_json(round, "client_to_target", &client_nonce, false));

                let nonce = rand::random::<[u8; 20]>();
                send.write_all(&nonce).await.context("send target nonce")?;
                send.flush().await.context("flush target nonce")?;
                let mut echo = [0u8; 20];
                recv.read_exact(&mut echo)
                    .await
                    .context("read target nonce echo")?;
                ensure!(echo == nonce, "target nonce echo mismatch");
                rounds.push(nonce_json(round, "target_to_client", &nonce, true));
            }
        }
    }
    send.shutdown().await.context("send stream FIN")?;
    let mut extra = [0u8; 1];
    ensure!(
        recv.read(&mut extra)
            .await
            .context("wait for peer stream EOF")?
            .is_none(),
        "peer sent bytes after the nonce exchanges"
    );
    match send.stopped().await {
        Ok(None) => {}
        Ok(Some(code)) => bail!("peer stopped nonce stream with application code {code}"),
        Err(error) => return Err(error.into()),
    }
    for round in &mut rounds {
        round["fin_complete"] = json!(true);
        round["peer_eof"] = json!(true);
        round["send_stopped_ok"] = json!(true);
    }
    Ok(rounds)
}

fn nonce_json(round: usize, direction: &str, nonce: &[u8; 20], verify_echo: bool) -> Value {
    let mut value = json!({
        "round":round,
        "direction":direction,
        "nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(nonce))
    });
    if verify_echo {
        value["echo_matches"] = json!(true);
    } else {
        value["echo_sent"] = json!(true);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn birthday_packet_is_bound_to_session_roles_and_signer() {
        let target_key = SecretKey::generate();
        let client_key = SecretKey::generate();
        let sid = Uuid::new_v4();
        let target_id = target_key.public();
        let client_id = client_key.public();
        let packet = encode_packet(
            &client_key,
            sid,
            target_id,
            client_id,
            Role::Client,
            PacketKind::Select,
            255,
        );
        let decoded = decode_packet(&packet, sid, target_id, client_id, client_id, Role::Client)
            .expect("valid signed packet");
        assert_eq!(decoded.kind as u8, PacketKind::Select as u8);
        assert_eq!(decoded.index, 255);
        assert!(
            decode_packet(
                &packet,
                Uuid::new_v4(),
                target_id,
                client_id,
                client_id,
                Role::Client,
            )
            .is_none()
        );
        assert!(
            decode_packet(&packet, sid, target_id, client_id, target_id, Role::Client,).is_none()
        );
        let mut tampered = packet;
        tampered[90] ^= 1;
        assert!(
            decode_packet(
                &tampered,
                sid,
                target_id,
                client_id,
                client_id,
                Role::Client,
            )
            .is_none()
        );
    }
}
