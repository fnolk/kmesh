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
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufReader, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader},
    time::{Instant, timeout_at},
};

const B_RELAY_URL: &str = "https://192.0.2.11:9443";
const B_QAD_PORT: u16 = 3478;
const PRIVATE_ALPN: &[u8] = b"kmesh/udp-ac-check/1";
// Matches the ALPN used by the archived successful AC run.
const PUBLIC_ALPN: &[u8] = b"kmesh/iroh-mechanism/1";
const ROUND_TIMEOUT: Duration = Duration::from_secs(40);
const MAPPING_TIMEOUT: Duration = Duration::from_secs(20);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(30);
const NONCES_PER_DIRECTION: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    fn peer_role(self) -> &'static str {
        match self {
            Self::Target => "client",
            Self::Client => "target",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelaySelection {
    Private,
    Public,
}

impl RelaySelection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Public => "public",
        }
    }

    fn alpn(self) -> &'static [u8] {
        match self {
            Self::Private => PRIVATE_ALPN,
            Self::Public => PUBLIC_ALPN,
        }
    }
}

struct Args {
    role: Role,
    relay_selection: RelaySelection,
    observe_mappings: bool,
    mapping_candidates: bool,
    ca_file: Option<PathBuf>,
    local_ip: Option<Ipv4Addr>,
    endpoint_secret_key_file: Option<PathBuf>,
}

#[derive(Deserialize)]
struct PeerReady {
    event: String,
    role: String,
    relay_mode: String,
    endpoint_id: String,
    global_v4: String,
    local_socket: String,
    relay_url: String,
    endpoint_addr: EndpointAddr,
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

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
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
    let deadline = Instant::now()
        + if args.observe_mappings {
            MAPPING_TIMEOUT
        } else {
            ROUND_TIMEOUT
        };
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow!("install ring provider"))?;
    }

    let secret_key = match args.relay_selection {
        RelaySelection::Private => {
            let path = args
                .endpoint_secret_key_file
                .as_ref()
                .context("private relay mode requires an enrolled Endpoint secret key file")?;
            let encoded = fs::read_to_string(path).context("read enrolled Endpoint secret key")?;
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded.trim())
                .context("decode enrolled Endpoint secret key")?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("Endpoint secret key must contain 32 bytes"))?;
            SecretKey::from_bytes(&bytes)
        }
        RelaySelection::Public => SecretKey::generate(),
    };
    let private_relay_url: iroh::RelayUrl =
        B_RELAY_URL.parse().context("parse fixed B relay URL")?;
    let mut private_allowed_relay_urls = BTreeSet::from([private_relay_url.clone()]);
    let mut relay_map_info = vec![json!({
        "url": private_relay_url,
        "qad_udp_port": B_QAD_PORT
    })];
    let builder = match args.relay_selection {
        RelaySelection::Private => {
            let ca_file = args
                .ca_file
                .as_ref()
                .context("private relay mode requires --ca-file")?;
            let mut ca_reader = BufReader::new(File::open(ca_file).context("open B CA file")?);
            let certs = rustls_pemfile::certs(&mut ca_reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("parse B CA file")?;
            ensure!(!certs.is_empty(), "B CA file contains no certificates");
            let ca_tls = CaTlsConfig::default().with_extra_roots(certs);
            let local_ip = args
                .local_ip
                .context("private relay mode requires --local-ip")?;
            let mut relays = vec![RelayConfig::new(
                private_relay_url.clone(),
                Some(RelayQuicConfig::new(B_QAD_PORT)),
            )];
            if args.observe_mappings || args.mapping_candidates {
                let official_relay = RelayMode::Default
                    .relay_map()
                    .relays::<Vec<_>>()
                    .into_iter()
                    .next()
                    .expect("the Iroh default relay map includes official relays");
                let official_qad_port = official_relay
                    .quic
                    .as_ref()
                    .expect("Iroh default relay configs enable QAD")
                    .port;
                relay_map_info.push(json!({
                    "url": official_relay.url,
                    "qad_udp_port": official_qad_port
                }));
                private_allowed_relay_urls.insert(official_relay.url.clone());
                relays.push(official_relay.as_ref().clone());
            }
            Endpoint::builder(presets::Minimal)
                .secret_key(secret_key)
                .alpns(vec![args.relay_selection.alpn().to_vec()])
                .relay_mode(RelayMode::Custom(RelayMap::from_iter(relays)))
                .ca_tls_config(ca_tls)
                .portmapper_config(PortmapperConfig::Disabled)
                .net_report_config(NetReportConfig::minimal())
                .clear_ip_transports()
                .bind_addr(SocketAddr::new(IpAddr::V4(local_ip), 0))
                .context("bind private diagnostic endpoint to IPv4")?
        }
        RelaySelection::Public => Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![args.relay_selection.alpn().to_vec()])
            .relay_mode(RelayMode::Default)
            .portmapper_config(PortmapperConfig::Disabled),
    };
    let endpoint = timeout_at(deadline, builder.bind())
        .await
        .context("bind endpoint before round deadline")??;
    let bound_socket = endpoint
        .bound_sockets()
        .into_iter()
        .find(|addr| {
            addr.is_ipv4()
                && args
                    .local_ip
                    .is_none_or(|local_ip| addr.ip() == IpAddr::V4(local_ip))
        })
        .context("read bound IPv4 UDP socket")?;

    let mut relay_status = endpoint.home_relay_status();
    loop {
        let statuses = relay_status.get();
        let b_relay_connected = statuses
            .iter()
            .any(|relay| relay.url() == &private_relay_url && relay.is_connected());
        if args.mapping_candidates && b_relay_connected {
            let actual_home_relay_url =
                endpoint.addr().relay_urls().next().map(ToString::to_string);
            emit(json!({
                "event": "relay_connectivity",
                "role": args.role.as_str(),
                "actual_home_relay_url": actual_home_relay_url,
                "b_relay_url": private_relay_url,
                "b_relay_connected": b_relay_connected,
                "connected_relays": statuses
                    .iter()
                    .filter(|relay| relay.is_connected())
                    .map(|relay| relay.url().to_string())
                    .collect::<Vec<_>>()
            }))?;
            break;
        }
        if !args.mapping_candidates && statuses.iter().any(|relay| relay.is_connected()) {
            break;
        }
        let auth_denied_reason = if args.mapping_candidates {
            statuses
                .iter()
                .find(|relay| relay.url() == &private_relay_url)
                .and_then(|relay| relay.auth_denied_reason())
        } else {
            statuses.iter().find_map(|relay| relay.auth_denied_reason())
        };
        if let Some(reason) = auth_denied_reason {
            if args.mapping_candidates {
                emit(json!({
                    "event": "relay_auth_denied",
                    "role": args.role.as_str(),
                    "b_relay_url": private_relay_url,
                    "b_relay_connected": false,
                    "actual_home_relay_url": endpoint
                        .addr()
                        .relay_urls()
                        .next()
                        .map(ToString::to_string),
                    "reason": reason
                }))?;
            } else {
                emit(
                    json!({"event":"relay_auth_denied","role":args.role.as_str(),"relay_mode":args.relay_selection.as_str(),"reason":reason}),
                )?;
            }
            bail!("selected Iroh relay denied the registered EndpointId: {reason}");
        }
        match timeout_at(deadline, relay_status.updated()).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => bail!("Iroh relay status watcher disconnected"),
            Err(_) if args.mapping_candidates => {
                let statuses = relay_status.get();
                let actual_home_relay_url =
                    endpoint.addr().relay_urls().next().map(ToString::to_string);
                emit(json!({
                    "event": "relay_connectivity_timeout",
                    "role": args.role.as_str(),
                    "b_relay_url": private_relay_url,
                    "b_relay_connected": statuses
                        .iter()
                        .any(|relay| relay.url() == &private_relay_url && relay.is_connected()),
                    "actual_home_relay_url": actual_home_relay_url,
                    "connected_relays": statuses
                        .iter()
                        .filter(|relay| relay.is_connected())
                        .map(|relay| relay.url().to_string())
                        .collect::<Vec<_>>()
                }))?;
                bail!(
                    "B private relay did not connect before deadline; actual home relay is {actual_home_relay_url:?}"
                );
            }
            Err(_) => bail!("wait for Iroh relay readiness timed out"),
        }
    }
    let mut report_watcher = endpoint.net_report();
    let report = timeout_at(deadline, report_watcher.initialized())
        .await
        .context("wait for initialized QAD report")?;
    if args.observe_mappings {
        emit(json!({
            "event": "mapping_report",
            "role": args.role.as_str(),
            "endpoint_id": endpoint.id().to_string(),
            "bound_socket": bound_socket,
            "relay_map": relay_map_info,
            "udp_v4": report.udp_v4,
            "global_v4": report.global_v4,
            "mapping_varies_by_dest_ipv4": report.mapping_varies_by_dest_ipv4,
            "udp_v6": report.udp_v6,
            "mapping_varies_by_dest_ipv6": report.mapping_varies_by_dest_ipv6
        }))?;
        timeout_at(deadline, endpoint.close())
            .await
            .context("close mapping observation endpoint")?;
        return Ok(());
    }
    let global_v4: SocketAddrV4 = report
        .global_v4
        .context("QAD report has no global IPv4 mapping")?;
    let observed_v4 = SocketAddr::V4(global_v4);
    let mut address_watcher = endpoint.watch_addr();
    loop {
        if address_watcher
            .get()
            .ip_addrs()
            .any(|candidate| candidate == &observed_v4)
        {
            break;
        }
        timeout_at(deadline, address_watcher.updated())
            .await
            .context("wait for QAD address publication")?
            .map_err(|_| anyhow!("endpoint address watcher disconnected"))?;
    }
    let own_addr = match args.relay_selection {
        RelaySelection::Private if args.mapping_candidates => endpoint.addr(),
        RelaySelection::Private => EndpointAddr::new(endpoint.id())
            .with_ip_addr(SocketAddr::V4(global_v4))
            .with_relay_url(private_relay_url.clone()),
        RelaySelection::Public => endpoint.addr(),
    };
    let own_home_relay_url = own_addr
        .relay_urls()
        .next()
        .cloned()
        .context("ready endpoint address has no home relay URL")?;
    let mut ready_event = json!({
        "event":"ready", "role":args.role.as_str(), "relay_mode":args.relay_selection.as_str(), "endpoint_id":endpoint.id().to_string(),
        "global_v4":global_v4, "local_socket":bound_socket, "endpoint_addr":own_addr,
        "relay_url":own_home_relay_url,
        "qad_server_config":match args.relay_selection {
            RelaySelection::Private => format!("192.0.2.11:{B_QAD_PORT}/udp"),
            RelaySelection::Public => "Iroh RelayMode::Default (UDP 7842)".to_owned(),
        }
    });
    if args.mapping_candidates {
        ready_event["relay_map"] = json!(relay_map_info);
    }
    emit(ready_event)?;

    let mut control = AsyncBufReader::new(tokio::io::stdin());
    let peer = read_peer(&mut control, deadline).await?;
    ensure!(peer.role == args.role.peer_role(), "peer role mismatch");
    ensure!(
        peer.relay_mode == args.relay_selection.as_str(),
        "peer selected a different relay mode"
    );
    let peer_id: EndpointId = peer.endpoint_id.parse().context("parse peer EndpointId")?;
    let peer_ip: SocketAddr = peer.global_v4.parse().context("parse peer QAD candidate")?;
    ensure!(peer_ip.is_ipv4(), "peer QAD candidate must be IPv4");
    ensure!(
        peer.endpoint_addr.id == peer_id,
        "peer EndpointAddr identity differs from peer EndpointId"
    );
    ensure!(
        peer.endpoint_addr
            .ip_addrs()
            .any(|candidate| candidate == &peer_ip),
        "peer EndpointAddr does not contain its QAD global IPv4 candidate"
    );
    let peer_relay_url: iroh::RelayUrl = peer
        .relay_url
        .parse()
        .context("parse peer home relay URL")?;
    let allowed_relay_urls = match args.relay_selection {
        RelaySelection::Private => private_allowed_relay_urls.clone(),
        RelaySelection::Public => RelayMode::Default.relay_map().urls::<BTreeSet<_>>(),
    };
    ensure!(
        allowed_relay_urls.contains(&peer_relay_url)
            && peer
                .endpoint_addr
                .relay_urls()
                .all(|url| allowed_relay_urls.contains(url)),
        "peer EndpointAddr includes a relay outside the selected library RelayMap"
    );
    ensure!(
        peer.endpoint_addr
            .relay_urls()
            .any(|url| url == &peer_relay_url),
        "peer home relay URL is absent from the full EndpointAddr"
    );
    let peer_local: SocketAddr = peer
        .local_socket
        .parse()
        .context("parse peer local socket")?;
    let peer_addr = peer.endpoint_addr.clone();
    emit(json!({
        "event":"peer_received", "role":args.role.as_str(), "local_endpoint_id":endpoint.id().to_string(),
        "peer_endpoint_id":peer_id.to_string(), "peer_global_v4_candidate":peer_ip, "peer_bound_socket":peer_local,
        "relay_mode":args.relay_selection.as_str(), "peer_home_relay_url":peer_relay_url
    }))?;

    let (data, auxiliary, outgoing, incoming, data_role) = match args.relay_selection {
        RelaySelection::Private => {
            let outgoing_fut = endpoint.connect(peer_addr.clone(), args.relay_selection.alpn());
            let incoming_fut = async {
                let incoming = endpoint
                    .accept()
                    .await
                    .context("endpoint closed while accepting reciprocal peer")?;
                incoming.await.context("complete accepted connection")
            };
            let (outgoing, incoming) = tokio::join!(
                timeout_at(deadline, outgoing_fut),
                timeout_at(deadline, incoming_fut)
            );
            let outgoing = outgoing
                .context("outgoing connection exceeded round deadline")?
                .context("connect to peer")?;
            let incoming = incoming.context("incoming connection exceeded round deadline")??;
            ensure!(
                outgoing.remote_id() == peer_id,
                "outgoing peer EndpointId mismatch"
            );
            ensure!(
                incoming.remote_id() == peer_id,
                "incoming peer EndpointId mismatch"
            );
            let (data, auxiliary) = match args.role {
                Role::Client => (outgoing.clone(), incoming.clone()),
                Role::Target => (incoming.clone(), outgoing.clone()),
            };
            (
                data,
                Some(auxiliary),
                Some(outgoing),
                Some(incoming),
                "client_outgoing",
            )
        }
        RelaySelection::Public => {
            let data = match args.role {
                Role::Target => {
                    let connection = timeout_at(
                        deadline,
                        endpoint.connect(peer_addr, args.relay_selection.alpn()),
                    )
                    .await
                    .context("target outgoing connection deadline")?
                    .context("target dial to public peer")?;
                    ensure!(
                        connection.remote_id() == peer_id,
                        "target dialed an unexpected EndpointId"
                    );
                    connection
                }
                Role::Client => {
                    let incoming = timeout_at(deadline, endpoint.accept())
                        .await
                        .context("client accept deadline")?
                        .context("client endpoint closed before target dial")?;
                    let connection = timeout_at(deadline, incoming)
                        .await
                        .context("complete accepted target connection deadline")?
                        .context("accept target dial")?;
                    ensure!(
                        connection.remote_id() == peer_id,
                        "client accepted an unexpected EndpointId"
                    );
                    connection
                }
            };
            let (outgoing, incoming) = match args.role {
                Role::Target => (Some(data.clone()), None),
                Role::Client => (None, Some(data.clone())),
            };
            (data, None, outgoing, incoming, "target_outgoing")
        }
    };
    emit(json!({
        "event":"connections_established", "role":args.role.as_str(),
        "local_endpoint_id":endpoint.id().to_string(), "peer_endpoint_id":peer_id.to_string(),
        "relay_mode":args.relay_selection.as_str(), "data_connection_role":data_role,
        "auxiliary_connection_role":if auxiliary.is_some() { Some("target_outgoing") } else { None },
        "outgoing_paths":outgoing.as_ref().map(|connection| paths_json(&path_samples(connection))),
        "incoming_paths":incoming.as_ref().map(|connection| paths_json(&path_samples(connection)))
    }))?;

    let direct_deadline = std::cmp::min(
        Instant::now() + DIRECT_TIMEOUT,
        deadline - Duration::from_secs(2),
    );
    let direct_started = Instant::now();
    let before_direct = match timeout_at(direct_deadline, wait_for_direct(&data)).await {
        Ok(Ok(paths)) => paths,
        Ok(Err(error)) => {
            emit(
                json!({"event":"direct_wait_error","role":args.role.as_str(),"elapsed_ms":direct_started.elapsed().as_millis(),"paths":paths_json(&path_samples(&data)),"error":format!("{error:#}")}),
            )?;
            bail!("selected direct path wait failed: {error:#}");
        }
        Err(_) => {
            emit(
                json!({"event":"direct_timeout","role":args.role.as_str(),"elapsed_ms":direct_started.elapsed().as_millis(),"paths":paths_json(&path_samples(&data))}),
            )?;
            bail!("no selected IPv4 direct path before deadline");
        }
    };
    let selected_before =
        selected_direct(&before_direct).context("selected IPv4 direct path missing")?;
    emit(json!({
        "event":"direct_selected","role":args.role.as_str(),"relay_mode":args.relay_selection.as_str(),"data_connection_role":data_role,
        "elapsed_ms":direct_started.elapsed().as_millis(),"selected_path":sample_json(selected_before),
        "paths":paths_json(&before_direct),"auxiliary_paths":auxiliary.as_ref().map(|connection| paths_json(&path_samples(connection)))
    }))?;

    ensure!(
        read_gate(&mut control, deadline).await? == "go",
        "coordinator aborted before nonce transfer"
    );
    let paths_before = path_samples(&data);
    let payload_path =
        selected_direct(&paths_before).context("direct path disappeared before payload")?;
    ensure!(
        payload_path.id == selected_before.id,
        "selected direct path changed before payload"
    );
    let local_opens_stream = match args.relay_selection {
        RelaySelection::Private => args.role == Role::Client,
        RelaySelection::Public => args.role == Role::Target,
    };
    let (mut send, mut recv) = if local_opens_stream {
        timeout_at(deadline, data.open_bi())
            .await
            .context("open stream timeout")??
    } else {
        timeout_at(deadline, data.accept_bi())
            .await
            .context("accept stream timeout")??
    };
    let nonce_started = Instant::now();
    let nonces = timeout_at(
        deadline,
        exchange_nonces(args.role, args.relay_selection, &mut send, &mut recv),
    )
    .await
    .context("nonce exchange timeout")??;
    drop(send);
    drop(recv);

    let paths_after = path_samples(&data);
    let selected_after = selected_direct(&paths_after);
    let deltas = path_deltas(&paths_before, &paths_after);
    let payload_path_delta = deltas
        .iter()
        .find(|delta| delta["path_id"].as_str() == Some(&payload_path.id));
    let direct_bytes_grew = payload_path_delta.is_some_and(|delta| {
        delta["tx_bytes_delta"].as_u64().unwrap_or(0) > 0
            && delta["rx_bytes_delta"].as_u64().unwrap_or(0) > 0
    });
    let matched_echoes = nonces
        .iter()
        .filter_map(|nonce| nonce["echo_matches"].as_bool())
        .collect::<Vec<_>>();
    let echoes_match = matched_echoes.len() == NONCES_PER_DIRECTION
        && matched_echoes.iter().all(|matched| *matched)
        && nonces
            .iter()
            .filter(|nonce| nonce["echo_sent"].as_bool() == Some(true))
            .count()
            == NONCES_PER_DIRECTION;
    let pass = echoes_match
        && selected_after.is_some_and(|selected| selected.id == payload_path.id)
        && direct_bytes_grew;
    emit(json!({
        "event":"nonce_result","role":args.role.as_str(),"relay_mode":args.relay_selection.as_str(),"data_connection_role":data_role,
        "nonce_bytes_per_direction":20*NONCES_PER_DIRECTION,"nonce_rounds":nonces,
        "nonce_echoes_match":echoes_match,"selected_direct_before":sample_json(payload_path),
        "selected_direct_after":selected_after.map(sample_json),"paths_before":paths_json(&paths_before),
        "paths_after":paths_json(&paths_after),"direct_path_udp_deltas":deltas,
        "direct_bytes_grew_both_directions":direct_bytes_grew,
        "auxiliary_paths_after":auxiliary.as_ref().map(|connection| paths_json(&path_samples(connection))),
        "nonce_elapsed_ms":nonce_started.elapsed().as_millis(),"pass":pass
    }))?;
    ensure!(
        pass,
        "direct path or bidirectional nonce/UDP evidence failed"
    );

    data.close(VarInt::from_u32(0), b"AC diagnostic complete");
    if let Some(auxiliary) = auxiliary {
        auxiliary.close(VarInt::from_u32(0), b"AC diagnostic complete");
    }
    timeout_at(deadline, endpoint.close())
        .await
        .context("endpoint cleanup deadline")?;
    emit(
        json!({"event":"complete","role":args.role.as_str(),"endpoint_id":endpoint.id().to_string(),"pass":true}),
    )?;
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut role = None;
    let mut relay_selection = None;
    let mut observe_mappings = false;
    let mut mapping_candidates = false;
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
            "--relay-mode" => {
                relay_selection = Some(match args.next().as_deref() {
                    Some("private") => RelaySelection::Private,
                    Some("public") => RelaySelection::Public,
                    _ => bail!("--relay-mode must be private or public"),
                })
            }
            "--observe-mappings" => observe_mappings = true,
            "--mapping-candidates" => mapping_candidates = true,
            "--ca-file" => ca_file = args.next().map(PathBuf::from),
            "--local-ip" => {
                local_ip = Some(
                    args.next()
                        .context("--local-ip requires IPv4")?
                        .parse::<Ipv4Addr>()
                        .context("parse local IPv4")?,
                )
            }
            "--endpoint-secret-key-file" => {
                endpoint_secret_key_file = args.next().map(PathBuf::from)
            }
            _ => {
                bail!(
                    "usage: udp_ac_check --role target|client --relay-mode private|public [--observe-mappings | --mapping-candidates] [--ca-file <PEM>] [--local-ip <IPv4> --endpoint-secret-key-file <FILE>]"
                )
            }
        }
    }
    let relay_selection = relay_selection.context("--relay-mode is required")?;
    ensure!(
        !(observe_mappings && mapping_candidates),
        "--observe-mappings and --mapping-candidates are mutually exclusive"
    );
    ensure!(
        !(observe_mappings || mapping_candidates) || relay_selection == RelaySelection::Private,
        "mapping observation modes are available for private mode only"
    );
    match relay_selection {
        RelaySelection::Private => {
            ensure!(ca_file.is_some(), "private relay mode requires --ca-file");
            ensure!(local_ip.is_some(), "private relay mode requires --local-ip");
            ensure!(
                endpoint_secret_key_file.is_some(),
                "private relay mode requires --endpoint-secret-key-file"
            );
        }
        RelaySelection::Public => ensure!(
            local_ip.is_none() && endpoint_secret_key_file.is_none(),
            "public mode uses a fresh key and the library's default socket bind"
        ),
    }
    Ok(Args {
        role: role.context("--role is required")?,
        relay_selection,
        observe_mappings,
        mapping_candidates,
        ca_file,
        local_ip,
        endpoint_secret_key_file,
    })
}

async fn read_peer(
    reader: &mut AsyncBufReader<tokio::io::Stdin>,
    deadline: Instant,
) -> Result<PeerReady> {
    let mut line = String::new();
    let n = timeout_at(deadline, reader.read_line(&mut line))
        .await
        .context("peer metadata deadline")?
        .context("read peer metadata")?;
    ensure!(n > 0, "control stdin closed before peer metadata");
    let peer: PeerReady = serde_json::from_str(&line).context("decode peer metadata")?;
    ensure!(peer.event == "ready", "expected ready event from peer");
    Ok(peer)
}

async fn read_gate(
    reader: &mut AsyncBufReader<tokio::io::Stdin>,
    deadline: Instant,
) -> Result<String> {
    let mut line = String::new();
    let n = timeout_at(deadline, reader.read_line(&mut line))
        .await
        .context("direct gate deadline")?
        .context("read direct gate")?;
    ensure!(n > 0, "control stdin closed before direct gate");
    let event = serde_json::from_str::<Value>(&line)?["event"]
        .as_str()
        .context("gate event missing")?
        .to_owned();
    ensure!(
        event == "go" || event == "abort",
        "gate event must be go or abort"
    );
    Ok(event)
}

async fn wait_for_direct(connection: &Connection) -> Result<Vec<PathSample>> {
    let mut changes = connection.paths_stream();
    loop {
        let current = path_samples(connection);
        if selected_direct(&current).is_some() {
            return Ok(current);
        }
        if changes.next().await.is_none() {
            bail!("path stream ended before IPv4 direct selection");
        }
    }
}

fn path_samples(connection: &Connection) -> Vec<PathSample> {
    connection
        .paths()
        .iter()
        .map(|p| {
            let stats = p.stats();
            let is_ipv4 = matches!(p.remote_addr(), TransportAddr::Ip(addr) if addr.is_ipv4());
            PathSample {
                id: format!("{:?}", p.id()),
                remote: p.remote_addr().to_string(),
                local: format!("{:?}", p.local_addr()),
                selected: p.is_selected(),
                is_ip: p.is_ip(),
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
    paths.iter().find(|p| p.selected && p.is_ip && p.is_ipv4)
}

fn sample_json(p: &PathSample) -> Value {
    json!({"path_id":p.id,"remote_addr":p.remote,"local_addr":p.local,"selected":p.selected,
        "is_ip":p.is_ip,"is_ipv4":p.is_ipv4,"udp_tx_datagrams":p.tx_datagrams,
        "udp_tx_bytes":p.tx_bytes,"udp_rx_datagrams":p.rx_datagrams,"udp_rx_bytes":p.rx_bytes})
}

fn paths_json(paths: &[PathSample]) -> Vec<Value> {
    paths.iter().map(sample_json).collect()
}

fn path_deltas(before: &[PathSample], after: &[PathSample]) -> Vec<Value> {
    after.iter().filter(|p| p.is_ip).map(|a| {
        let b = before.iter().find(|p| p.id == a.id);
        let (btxd,btxb,brxd,brxb) = b.map_or((0,0,0,0), |p| (p.tx_datagrams,p.tx_bytes,p.rx_datagrams,p.rx_bytes));
        json!({"path_id":a.id,"remote_addr":a.remote,"selected_after":a.selected,
            "tx_datagrams_before":btxd,"tx_datagrams_after":a.tx_datagrams,"tx_datagrams_delta":a.tx_datagrams.saturating_sub(btxd),
            "tx_bytes_before":btxb,"tx_bytes_after":a.tx_bytes,"tx_bytes_delta":a.tx_bytes.saturating_sub(btxb),
            "rx_datagrams_before":brxd,"rx_datagrams_after":a.rx_datagrams,"rx_datagrams_delta":a.rx_datagrams.saturating_sub(brxd),
            "rx_bytes_before":brxb,"rx_bytes_after":a.rx_bytes,"rx_bytes_delta":a.rx_bytes.saturating_sub(brxb)})
    }).collect()
}

async fn exchange_nonces(
    role: Role,
    relay_selection: RelaySelection,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<Vec<Value>> {
    let mut out = Vec::with_capacity(NONCES_PER_DIRECTION * 2);
    for round in 1..=NONCES_PER_DIRECTION {
        match (relay_selection, role) {
            (RelaySelection::Private, Role::Client) => {
                let nonce = rand::random::<[u8; 20]>();
                send.write_all(&nonce).await?;
                send.flush().await?;
                let mut echo = [0; 20];
                recv.read_exact(&mut echo).await?;
                ensure!(echo == nonce, "client nonce echo mismatch");
                out.push(json!({"round":round,"direction":"client_to_target","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(nonce)),"echo_matches":true}));
                let mut target_nonce = [0; 20];
                recv.read_exact(&mut target_nonce).await?;
                send.write_all(&target_nonce).await?;
                send.flush().await?;
                out.push(json!({"round":round,"direction":"target_to_client","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(target_nonce)),"echo_sent":true}));
            }
            (RelaySelection::Private, Role::Target) => {
                let mut client_nonce = [0; 20];
                recv.read_exact(&mut client_nonce).await?;
                send.write_all(&client_nonce).await?;
                send.flush().await?;
                out.push(json!({"round":round,"direction":"client_to_target","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(client_nonce)),"echo_sent":true}));
                let nonce = rand::random::<[u8; 20]>();
                send.write_all(&nonce).await?;
                send.flush().await?;
                let mut echo = [0; 20];
                recv.read_exact(&mut echo).await?;
                ensure!(echo == nonce, "target nonce echo mismatch");
                out.push(json!({"round":round,"direction":"target_to_client","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(nonce)),"echo_matches":true}));
            }
            (RelaySelection::Public, Role::Target) => {
                let nonce = rand::random::<[u8; 20]>();
                send.write_all(&nonce).await?;
                send.flush().await?;
                let mut echo = [0; 20];
                recv.read_exact(&mut echo).await?;
                ensure!(echo == nonce, "target nonce echo mismatch");
                out.push(json!({"round":round,"direction":"target_to_client","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(nonce)),"echo_matches":true}));
                let mut client_nonce = [0; 20];
                recv.read_exact(&mut client_nonce).await?;
                send.write_all(&client_nonce).await?;
                send.flush().await?;
                out.push(json!({"round":round,"direction":"client_to_target","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(client_nonce)),"echo_sent":true}));
            }
            (RelaySelection::Public, Role::Client) => {
                let mut target_nonce = [0; 20];
                recv.read_exact(&mut target_nonce).await?;
                send.write_all(&target_nonce).await?;
                send.flush().await?;
                out.push(json!({"round":round,"direction":"target_to_client","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(target_nonce)),"echo_sent":true}));
                let nonce = rand::random::<[u8; 20]>();
                send.write_all(&nonce).await?;
                send.flush().await?;
                let mut echo = [0; 20];
                recv.read_exact(&mut echo).await?;
                ensure!(echo == nonce, "client nonce echo mismatch");
                out.push(json!({"round":round,"direction":"client_to_target","nonce_sha256":URL_SAFE_NO_PAD.encode(Sha256::digest(nonce)),"echo_matches":true}));
            }
        }
    }
    send.shutdown().await.context("send stream FIN")?;
    let mut extra = [0; 1];
    ensure!(
        recv.read(&mut extra)
            .await
            .context("wait for peer stream FIN")?
            .is_none(),
        "peer sent bytes after the expected nonce exchanges"
    );
    match send.stopped().await {
        Ok(None) => {}
        Ok(Some(code)) => bail!("peer stopped nonce stream with code {code}"),
        Err(error) => return Err(error.into()),
    }
    Ok(out)
}

fn emit(value: Value) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn init_tracing() {
    let default =
        "warn,iroh::socket::transports=trace,iroh::socket::remote_map::remote_state=debug";
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let filter = if std::env::args()
        .any(|arg| arg == "--observe-mappings" || arg == "--mapping-candidates")
    {
        filter.add_directive(
            "iroh::net_report=debug"
                .parse()
                .expect("static NetReport log directive is valid"),
        )
    } else {
        filter
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
